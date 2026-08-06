;;; record-layer.lisp --- TLS 1.3 Record Layer Protocol
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Implements the TLS 1.3 record layer (RFC 8446 Section 5).

(in-package #:pure-tls)

;;;; TLS Record Structure
;;;
;;; Plaintext record (before encryption):
;;;   struct {
;;;     ContentType type;
;;;     ProtocolVersion legacy_record_version = 0x0303;  /* TLS 1.2 */
;;;     uint16 length;
;;;     opaque fragment[TLSPlaintext.length];
;;;   } TLSPlaintext;
;;;
;;; Ciphertext record (after encryption, TLS 1.3):
;;;   struct {
;;;     ContentType opaque_type = application_data; /* 23 */
;;;     ProtocolVersion legacy_record_version = 0x0303;
;;;     uint16 length;
;;;     opaque encrypted_record[TLSCiphertext.length];
;;;   } TLSCiphertext;

(defstruct tls-record
  "A TLS record."
  (content-type 0 :type octet)
  (version +tls-1.2+ :type fixnum)
  (fragment nil :type (or null octet-vector)))

;;;; Record Layer I/O

(defun read-exact-bytes (stream buffer count &optional request-context)
  "Read exactly COUNT bytes from STREAM into BUFFER.
   Loops until all bytes are read or EOF is reached.
   Returns the number of bytes actually read (may be less than COUNT at EOF).
   If REQUEST-CONTEXT is provided, checks for deadline/cancellation before each read."
  (let ((total-read 0))
    (loop while (< total-read count)
          do (check-tls-context)
             (let ((bytes-read (read-sequence buffer stream
                                              :start total-read
                                              :end count)))
               (when (= bytes-read total-read)
                 ;; No progress - EOF reached
                 (return total-read))
               (setf total-read bytes-read)))
    total-read))

(defun read-tls-record (stream &optional request-context)
  "Read a TLS record from STREAM.
   Returns a TLS-RECORD structure or signals an error.
   Uses a stack-allocated 5-byte header and a pool-allocated read buffer
   to avoid per-record heap allocation.  The read buffer is recycled via
   the enclosing WITH-BUFFER-CONTEXT; the returned fragment is an
   exact-sized copy safe for use beyond the context scope.
   Properly handles short reads from the underlying stream.
   Validates legacy_record_version per RFC 8446 Section 5.1.
   If REQUEST-CONTEXT is provided, checks for deadline/cancellation during reads."
  (let ((header (make-array 5 :element-type '(unsigned-byte 8) :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 8) (5)) header)
             (dynamic-extent header))
    ;; Read 5-byte header (loop until complete or EOF)
    (let ((bytes-read (read-exact-bytes stream header 5 request-context)))
      (declare (type fixnum bytes-read))
      (when (zerop bytes-read)
        (error 'tls-connection-closed :clean nil))
      (when (< bytes-read 5)
        (error 'tls-decode-error
               :message (format nil "Incomplete record header: expected 5 bytes, got ~D"
                                bytes-read))))
    ;; Parse header
    (let* ((content-type (aref header 0))
           (version (decode-uint16 header 1))
           (length (decode-uint16 header 3)))
      (declare (type fixnum content-type version length))
      ;; Validate content type - must be a valid TLS content type (20-24)
      ;; This quickly rejects SSLv2 records which have high-bit-set bytes
      ;; in position 0, preventing us from waiting forever for invalid lengths.
      (unless (and (>= content-type +content-type-change-cipher-spec+)  ; 20
                   (<= content-type 24))  ; heartbeat is 24
        (error 'tls-decode-error
               :message (format nil ":WRONG_VERSION_NUMBER: Invalid content type ~D (not a valid TLS record)"
                                content-type)))
      ;; RFC 8446 Section 5.1: legacy_record_version SHOULD be 0x0303 for
      ;; all TLS 1.3 records, but implementations MUST NOT check this field.
      ;; Accept any record version for maximum compatibility.
      ;; Validate length
      (when (> length +max-record-size-with-padding+)
        (error 'tls-record-overflow :size length))
      ;; Read into a pool-allocated buffer (tier-sized, recycled by context
      ;; exit), then copy exact LENGTH bytes into the returned fragment.
      ;; The pool buffer avoids per-record GC pressure on the read path.
      (let ((read-buffer (if *buffer-context*
                             (buffer-pool-allocate *buffer-pool* length)
                             (make-octet-vector length))))
        (let ((bytes-read (read-exact-bytes stream read-buffer length request-context)))
          (declare (type fixnum bytes-read))
          (when (< bytes-read length)
            (error 'tls-decode-error
                   :message (format nil "Incomplete record fragment: expected ~D bytes, got ~D"
                                    length bytes-read))))
        ;; Copy exact-size fragment from pool buffer.  The pool buffer
        ;; stays on the context list and is recycled on scope exit.
        (let ((fragment (make-octet-vector length)))
          (replace fragment read-buffer :end2 length)
          (make-tls-record :content-type content-type
                           :version version
                           :fragment fragment))))))

(defun write-tls-record (stream record)
  "Write a TLS record to STREAM.  Uses stack-allocated 5-byte header
   instead of heap-allocating via make-octet-vector."
  (let* ((fragment (tls-record-fragment record))
         (length (length fragment))
         (header (make-array 5 :element-type '(unsigned-byte 8) :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 8) (5)) header)
             (type fixnum length)
             (dynamic-extent header))
    ;; Validate length
    (when (> length +max-record-size-with-padding+)
      (error 'tls-record-overflow :size length))
    ;; Build header
    (setf (aref header 0) (tls-record-content-type record))
    (setf (aref header 1) (ldb (byte 8 8) (tls-record-version record)))
    (setf (aref header 2) (ldb (byte 8 0) (tls-record-version record)))
    (setf (aref header 3) (ldb (byte 8 8) length))
    (setf (aref header 4) (ldb (byte 8 0) length))
    ;; Write header and fragment
    (write-sequence header stream)
    (write-sequence fragment stream)
    (force-output stream)))

(defun make-plaintext-record (content-type data)
  "Create a plaintext TLS record."
  (make-tls-record :content-type content-type
                   :version +tls-1.2+
                   :fragment data))

;;;; Record Encryption/Decryption

(defconstant +max-ccs-messages+ 32
  "Maximum number of change_cipher_spec messages allowed (DoS protection).")

(defstruct (record-layer (:constructor %make-record-layer))
  "TLS record layer state."
  (read-cipher nil :type (or null aead-cipher))
  (write-cipher nil :type (or null aead-cipher))
  (cipher-suite 0 :type fixnum)
  (stream nil)
  (max-send-fragment +max-record-size+ :type fixnum)
  (ccs-count 0 :type fixnum)
  (request-context nil :type t)
  ;; Engine limits.  The protocol ceilings are fixed by RFC 8446 and stay
  ;; constants; these are the per-layer allocation and acceptance budgets,
  ;; which a caller may want to set lower than the ceiling.  The defaults are
  ;; the ceilings, so a layer built without them behaves as it always has.
  (max-in-ciphertext +max-record-size-with-padding+ :type fixnum)
  (max-in-plaintext +max-record-size+ :type fixnum)
  (max-out-plaintext +max-record-size+ :type fixnum)
  ;; MAX-OUT-CIPHERTEXT is deliberately consulted by nothing.  It records the
  ;; budget a caller asked for and completes the set of four, but no honest
  ;; check can be built from it, and the two places one could go are both
  ;; wrong.
  ;;
  ;; Before encryption the ciphertext size is not known.  The padding policy is
  ;; an arbitrary function of the fragment, so bounding the fragment by a
  ;; ciphertext budget in advance means guessing what that function will decide,
  ;; and a guess that comes in low silently shrinks records for no stated
  ;; reason while one that comes in high does not bound anything.
  ;;
  ;; After encryption the size is known and the refusal is too late.  Producing
  ;; the ciphertext has already advanced the write sequence number, so rejecting
  ;; the record at that point spends a sequence number on octets that never
  ;; reach the peer, and the peer counts differently from us for the rest of the
  ;; connection.  That failure surfaces as records that will not authenticate,
  ;; which reads as tampering rather than as a budget check.
  ;;
  ;; Enforcing this budget therefore needs the padding policy to state a bound
  ;; the layer can compute up front.  It is a change to that contract, not a
  ;; missing call.
  (max-out-ciphertext +max-record-size-with-padding+ :type fixnum)
  ;; Inbound cursor.  IN-PHASE says whether we are between records, partway
  ;; through the 5-byte header, or partway through the body.
  ;;
  ;; IN-HEADER carries the header bytes seen so far packed into one integer,
  ;; most significant byte first: content type in bits 32-39, legacy version
  ;; in bits 16-31, body length in bits 0-15.  Forty bits fits inside a
  ;; 62-bit SBCL fixnum, so a partially read header is an immediate value and
  ;; never reaches the heap.  The three fields are extracted on demand by the
  ;; accessors below rather than stored again.  IN-HEADER-SEEN counts the
  ;; header bytes accumulated, 0 through 5.
  (in-phase :idle :type (member :idle :header :body))
  (in-header 0 :type fixnum)
  (in-header-seen 0 :type fixnum)
  (in-body nil :type (or null octet-vector))
  (in-body-filled 0 :type fixnum)
  ;; Inbound plaintext.  IN-PLAINTEXT holds bytes that have already been
  ;; decrypted but that the caller has not taken yet, and IN-PLAINTEXT-START is
  ;; how far into them the caller has read.  The cursors above track the
  ;; ciphertext side of the same direction; these two are its plaintext side,
  ;; and mirror OUT-SOURCE / OUT-START on the outbound path.
  (in-plaintext nil :type (or null octet-vector))
  (in-plaintext-start 0 :type fixnum)
  ;; A finished record whose content type is not application data waits here
  ;; instead, whole, until the caller takes it.  The data phase still carries
  ;; alerts and post-handshake messages such as NewSessionTicket and KeyUpdate,
  ;; and adding one of those to IN-PLAINTEXT would splice it into the
  ;; application's byte stream where nothing downstream can tell it apart from
  ;; payload.
  (in-message nil :type (or null octet-vector))
  (in-message-content-type 0 :type fixnum)
  ;; Set once the caller has said the transport will send no more octets.  The
  ;; layer cannot find this out for itself: it is handed octets and never reads
  ;; a descriptor, so an empty hand-over means the transport had nothing this
  ;; time round and nothing more than that.
  (in-eof nil :type boolean)
  ;; Outbound cursor.  OUT-RECORD holds one already encrypted record that the
  ;; transport has not finished accepting, and OUT-RECORD-SENT is how many of
  ;; its bytes went out.
  ;;
  ;; The ciphertext has to be retained because encryption is not repeatable.
  ;; Producing it advanced the write direction's AEAD sequence number, and
  ;; that advance cannot be undone.  Encrypting the same fragment a second
  ;; time to retry a short write either reuses the nonce the first attempt
  ;; consumed, which breaks AEAD confidentiality outright rather than merely
  ;; failing the connection, or burns another sequence number and leaves the
  ;; peer's counter behind ours.  The only safe resumption is byte-wise, from
  ;; the ciphertext we already have.
  ;;
  ;; Next to the plaintext cursor below this pair reads as redundant
  ;; buffering, and folding it away into re-encrypt-and-retry looks tidier and
  ;; passes every test we have.  It also puts nonce reuse back.
  (out-record nil :type (or null octet-vector))
  (out-record-sent 0 :type fixnum)
  ;; The plaintext still being fragmented into records: the source vector and
  ;; the half-open span of it that has not yet been turned into records, plus
  ;; the content type every record cut from it carries.
  (out-source nil :type (or null octet-vector))
  (out-start 0 :type fixnum)
  (out-end 0 :type fixnum)
  (out-content-type 0 :type fixnum))

(declaim (inline record-layer-in-content-type
                 record-layer-in-version
                 record-layer-in-length))

(defun record-layer-in-content-type (layer)
  "Content type of the inbound record header accumulated in LAYER.
   Meaningful once RECORD-LAYER-IN-HEADER-SEEN has reached 1."
  (declare (type record-layer layer))
  (ldb (byte 8 32) (record-layer-in-header layer)))

(defun record-layer-in-version (layer)
  "Legacy record version of the inbound record header accumulated in LAYER.
   Meaningful once RECORD-LAYER-IN-HEADER-SEEN has reached 3."
  (declare (type record-layer layer))
  (ldb (byte 16 16) (record-layer-in-header layer)))

(defun record-layer-in-length (layer)
  "Body length of the inbound record header accumulated in LAYER.
   Meaningful once RECORD-LAYER-IN-HEADER-SEEN has reached 5."
  (declare (type record-layer layer))
  (ldb (byte 16 0) (record-layer-in-header layer)))

(defun make-record-layer (stream &key (max-send-fragment +max-record-size+)
                                      request-context
                                      (max-in-ciphertext +max-record-size-with-padding+)
                                      (max-in-plaintext +max-record-size+)
                                      (max-out-plaintext +max-record-size+)
                                      (max-out-ciphertext +max-record-size-with-padding+))
  "Create a new record layer for the given stream.
   MAX-SEND-FRAGMENT sets the maximum plaintext size for outgoing records.
   REQUEST-CONTEXT is an optional cl-cancel context for timeout/cancellation support.
   MAX-IN-CIPHERTEXT, MAX-IN-PLAINTEXT, MAX-OUT-PLAINTEXT and MAX-OUT-CIPHERTEXT
   are this layer's own budgets for the four record buffers.  They default to
   the protocol ceilings, which is what the layer has always accepted; a caller
   that wants a smaller memory footprint per connection can set them lower."
  (%make-record-layer :stream stream
                      :max-send-fragment max-send-fragment
                      :request-context request-context
                      :max-in-ciphertext max-in-ciphertext
                      :max-in-plaintext max-in-plaintext
                      :max-out-plaintext max-out-plaintext
                      :max-out-ciphertext max-out-ciphertext))

;;; A live connection is adopted by handing over the cipher objects themselves,
;;; never key material.  An AEAD cipher owns its record sequence number, and
;;; that counter is as much a part of the connection's state as the key is: it
;;; feeds the per-record nonce on the write side, and it has to agree with the
;;; peer's count on the read side.  Rebuilding a cipher from the same key and
;;; IV yields an object that looks correct in every visible respect and starts
;;; counting from zero, which rewinds both directions at once.  On the write
;;; side that repeats nonces the connection has already spent, and the loss is
;;; confidentiality rather than the connection.  On the read side the next
;;; record simply fails to authenticate, and it presents as the peer breaking
;;; protocol rather than as anything to do with the handover.
;;;
;;; This constructor therefore accepts no key and no IV, and has no way to
;;; build a cipher.  A caller holding only key material cannot reach it at all,
;;; which is the point: avoiding the reset is not something a later reader has
;;; to know about in order to get right.
(defun adopt-record-layer (stream &key read-cipher write-cipher cipher-suite
                                       in-plaintext (in-plaintext-start 0)
                                       (max-send-fragment +max-record-size+)
                                       request-context
                                       (max-in-ciphertext +max-record-size-with-padding+)
                                       (max-in-plaintext +max-record-size+)
                                       (max-out-plaintext +max-record-size+)
                                       (max-out-ciphertext +max-record-size-with-padding+))
  "Build a record layer for STREAM from a connection that is already established.

   READ-CIPHER and WRITE-CIPHER are the live AEAD-CIPHER objects the handshake
   finished with, and both are required.  They are stored by reference, so the
   sequence number each one carries continues from wherever the handshake left
   it.  CIPHER-SUITE defaults to the suite the read cipher was built for.

   IN-PLAINTEXT is decrypted payload that has arrived but not yet been handed
   to a reader, and IN-PLAINTEXT-START is how much of it was already taken.
   The inbound ciphertext cursors are set idle, which is what a blocking
   handshake leaves behind: whole records were consumed, so no partial record
   is outstanding.

   The remaining arguments carry the meanings they have for MAKE-RECORD-LAYER."
  (unless (aead-cipher-p read-cipher)
    (error "adopt-record-layer: READ-CIPHER must be a live AEAD-CIPHER, got ~S."
           read-cipher))
  (unless (aead-cipher-p write-cipher)
    (error "adopt-record-layer: WRITE-CIPHER must be a live AEAD-CIPHER, got ~S."
           write-cipher))
  (check-type in-plaintext (or null octet-vector))
  (check-type in-plaintext-start fixnum)
  (unless (<= 0 in-plaintext-start (length (or in-plaintext #())))
    (error "adopt-record-layer: IN-PLAINTEXT-START ~S lies outside IN-PLAINTEXT."
           in-plaintext-start))
  (%make-record-layer :stream stream
                      :read-cipher read-cipher
                      :write-cipher write-cipher
                      :cipher-suite (or cipher-suite
                                        (aead-cipher-cipher-suite read-cipher))
                      :max-send-fragment max-send-fragment
                      :request-context request-context
                      :max-in-ciphertext max-in-ciphertext
                      :max-in-plaintext max-in-plaintext
                      :max-out-plaintext max-out-plaintext
                      :max-out-ciphertext max-out-ciphertext
                      ;; Idle inbound ciphertext cursors, stated here rather
                      ;; than left to the slot defaults, so the assumption is
                      ;; visible at the point the layer is built.
                      :in-phase :idle
                      :in-header 0
                      :in-header-seen 0
                      :in-body nil
                      :in-body-filled 0
                      :in-plaintext in-plaintext
                      :in-plaintext-start in-plaintext-start))

;;; Serving the plaintext held in IN-PLAINTEXT.
;;;
;;; The two functions below are the whole of a reader's interface to it, and
;;; they are deliberately stated in terms of octets and a caller-owned
;;; destination.  A reader driven by an event loop has no Gray stream to read
;;; through and no way to block, so it cannot be handed a stream; it wakes with
;;; a buffer it already owns, asks how much is there, and takes what fits.
;;;
;;; TAKE writes into that buffer rather than returning a fresh vector.  The
;;; caller almost always has somewhere for the octets to go already, and this
;;; path runs once per wakeup on every connection, so returning a vector would
;;; put an allocation on it that the caller immediately copies out of and
;;; discards.  It also makes partial consumption the ordinary case rather than a
;;; special one: the caller states how much room it has, and the cursor advances
;;; by exactly what was written.

(defun record-layer-plaintext-available (layer)
  "How many decrypted octets LAYER is holding that no reader has taken yet."
  (declare (type record-layer layer))
  (let ((held (record-layer-in-plaintext layer)))
    (if held
        (- (length held) (record-layer-in-plaintext-start layer))
        0)))

(defun record-layer-take-plaintext (layer buffer &key (start 0) (end (length buffer)))
  "Move LAYER's held plaintext into BUFFER between START and END.

   Writes as many octets as will fit, advances the cursor past them, and returns
   how many were written.  A return of zero means the layer is holding nothing,
   which is a normal answer rather than an error: it is what a reader sees once
   it has drained the handover and has to wait on the transport for more.

   Draining releases the vector instead of leaving an exhausted one behind, so
   the layer stops holding decrypted octets the moment the last of them is taken
   and an empty layer has one representation rather than two."
  (declare (type record-layer layer)
           (type octet-vector buffer))
  (unless (<= 0 start end (length buffer))
    (error "record-layer-take-plaintext: [~D,~D) lies outside a buffer of ~D octets."
           start end (length buffer)))
  (let ((held (record-layer-in-plaintext layer)))
    (if (null held)
        0
        (let* ((from (record-layer-in-plaintext-start layer))
               (available (- (length held) from))
               (taken (min available (- end start))))
          (declare (type fixnum from available taken))
          (when (plusp taken)
            (replace buffer held
                     :start1 start :end1 (+ start taken)
                     :start2 from :end2 (+ from taken)))
          (if (= taken available)
              (setf (record-layer-in-plaintext layer) nil
                    (record-layer-in-plaintext-start layer) 0)
              (setf (record-layer-in-plaintext-start layer) (+ from taken)))
          taken))))

(defun record-layer-install-keys (layer direction key iv cipher-suite)
  "Install encryption keys for the specified direction (:read or :write)."
  (let ((cipher (make-aead cipher-suite key iv)))
    (ecase direction
      (:read (setf (record-layer-read-cipher layer) cipher))
      (:write (setf (record-layer-write-cipher layer) cipher)))
    (setf (record-layer-cipher-suite layer) cipher-suite)))

(defun record-layer-read (layer)
  "Read and potentially decrypt a record from the record layer.
   Returns (VALUES content-type plaintext).
   Uses WITH-BUFFER-CONTEXT so pool-allocated read buffers inside
   read-tls-record are automatically recycled on scope exit.
   The returned fragment is always a fresh exact-sized buffer safe
   for use beyond the context scope.

   Signals TLS-PLAINTEXT-PENDING if the layer is still holding decrypted octets
   that no reader has taken.  Those octets came off the connection ahead of
   anything this call would read, so serving a new record first would deliver
   the stream out of order.  RECORD-LAYER-TAKE-PLAINTEXT drains them; this
   function will not, because a caller that asked for a record and was handed
   held-over plaintext instead has been answered a different question."
  (let ((pending (record-layer-plaintext-available layer)))
    (when (plusp pending)
      (error 'tls-plaintext-pending :available pending)))
  (check-tls-context)
  (with-buffer-context (*buffer-pool*)
    (let* ((record (read-tls-record (record-layer-stream layer)
                                     (record-layer-request-context layer)))
           (content-type (tls-record-content-type record))
           (fragment (tls-record-fragment record))
           (cipher (record-layer-read-cipher layer)))
      ;; Handle change_cipher_spec (ignored in TLS 1.3 but may be sent)
      (when (= content-type +content-type-change-cipher-spec+)
        ;; Count CCS messages to prevent DoS
        (incf (record-layer-ccs-count layer))
        (when (> (record-layer-ccs-count layer) +max-ccs-messages+)
          (record-layer-write-alert layer +alert-level-fatal+ +alert-unexpected-message+)
          (error 'tls-handshake-error
                 :message ":TOO_MANY_EMPTY_FRAGMENTS: Too many change_cipher_spec messages"))
        ;; Just return and let caller handle/ignore
        (return-from record-layer-read
          (values content-type fragment)))
      ;; If encryption is established, all records MUST be encrypted (content-type 23)
      ;; RFC 8446 Section 5.1: After the handshake keys are installed, all records
      ;; except CCS must use the encrypted record format (application_data wrapper)
      (when cipher
        (unless (= content-type +content-type-application-data+)
          (record-layer-write-alert layer +alert-level-fatal+ +alert-unexpected-message+)
          (error 'tls-handshake-error
                 :message (format nil ":INVALID_OUTER_RECORD_TYPE: Expected encrypted record (23), got ~D"
                                 content-type)))
        ;; Decrypt the record — stack-allocate the 5-byte AAD header
        (let ((header (make-array 5 :element-type '(unsigned-byte 8) :initial-element 0)))
          (declare (type (simple-array (unsigned-byte 8) (5)) header)
                   (dynamic-extent header))
          (setf (aref header 0) content-type
                (aref header 1) (ldb (byte 8 8) (tls-record-version record))
                (aref header 2) (ldb (byte 8 0) (tls-record-version record))
                (aref header 3) (ldb (byte 8 8) (length fragment))
                (aref header 4) (ldb (byte 8 0) (length fragment)))
          ;; tls13-decrypt-record returns (plaintext, content-type)
          ;; We need to return (content-type, plaintext)
          ;; Catch record overflow to send alert before re-raising
          (handler-bind ((tls-record-overflow
                           (lambda (c)
                             (declare (ignore c))
                             (record-layer-write-alert layer
                                                       +alert-level-fatal+
                                                       +alert-record-overflow+))))
            (multiple-value-bind (plaintext inner-content-type)
                (tls13-decrypt-record cipher fragment header)
              (return-from record-layer-read
                (values inner-content-type plaintext))))))
      ;; No encryption - return plaintext record
      (values content-type fragment))))

(defun record-layer-write (layer content-type data &key (start 0) (end (length data)))
  "Write and potentially encrypt a record to the record layer.
   START/END bound the region of DATA to send, avoiding a subseq copy when the
   caller already holds the payload in a larger buffer."
  (let* ((cipher (record-layer-write-cipher layer))
         (stream (record-layer-stream layer)))
    (if cipher
        ;; Encrypted write.  tls13-encrypt-record copies DATA[start,end) into
        ;; its own inner buffer, so no slice needs to be materialized here.
        (let* ((encrypted (tls13-encrypt-record cipher content-type data
                                                :start start :end end))
               (record (make-tls-record
                        :content-type +content-type-application-data+
                        :version +tls-1.2+
                        :fragment encrypted)))
          (write-tls-record stream record))
        ;; Plaintext write - only materialize a slice when one is requested.
        (let ((record (make-plaintext-record
                       content-type
                       (if (and (= start 0) (= end (length data)))
                           data
                           (subseq data start end)))))
          (write-tls-record stream record)))))

(defun record-layer-write-alert (layer level description)
  "Write an alert record."
  (let ((data (octet-vector level description)))
    (record-layer-write layer +content-type-alert+ data)))

(defun record-layer-write-handshake (layer handshake-data)
  "Write a handshake record, fragmenting if necessary."
  (record-layer-write-fragmented layer +content-type-handshake+ handshake-data))

(defun record-layer-write-application-data (layer data &key (start 0) (end (length data)))
  "Write application data, fragmenting if necessary.
   START/END bound the region of DATA to send."
  (record-layer-write-fragmented layer +content-type-application-data+ data
                                 :start start :end end))

(defun record-layer-write-change-cipher-spec (layer)
  "Write a dummy change_cipher_spec record for middlebox compatibility.
   Per RFC 8446 Appendix D.4, TLS 1.3 implementations SHOULD send
   a single CCS record immediately after the first ClientHello (client)
   or ServerHello (server) for compatibility with broken middleboxes.
   The CCS record is always sent unencrypted with content byte 0x01."
  (let* ((ccs-data (octet-vector 1))  ; Single byte 0x01
         (record (make-tls-record :content-type +content-type-change-cipher-spec+
                                  :version +tls-1.2+
                                  :fragment ccs-data)))
    (write-tls-record (record-layer-stream layer) record)))

;;;; Record Fragmentation

(defun fragment-data (data max-size)
  "Split DATA into fragments of at most MAX-SIZE bytes.
   Returns a list of octet vectors."
  (if (<= (length data) max-size)
      (list data)
      (loop for start from 0 below (length data) by max-size
            collect (subseq data start (min (+ start max-size) (length data))))))

(defun record-layer-write-fragmented (layer content-type data
                                      &key (start 0) (end (length data)))
  "Write DATA[start,end) as potentially multiple records, fragmenting if
   necessary.  Respects the max-send-fragment setting of the record layer.
   MAX-SEND-FRAGMENT is the maximum plaintext payload size before encryption.
   Fragments are written as bounded slices of DATA, so no per-fragment subseq
   copies are allocated."
  (let ((max-size (record-layer-max-send-fragment layer)))
    (if (<= (- end start) max-size)
        (record-layer-write layer content-type data :start start :end end)
        (loop for s from start below end by max-size
              do (record-layer-write layer content-type data
                                     :start s :end (min end (+ s max-size)))))))

;;;; Sending Records Without a Stream
;;;
;;; The writers above hand a record to a stream and return once the stream has
;;; taken all of it.  A caller driven by an event loop has no stream and cannot
;;; wait: it asks what it should try to send, sends whatever the transport
;;; happens to accept this time round, and comes back later for the rest.  The
;;; functions below are the whole of that interface, and like the inbound pair
;;; they speak in octets and spans rather than in anything the caller could
;;; mistake for a connection.
;;;
;;; Nothing above changes.  RECORD-LAYER-WRITE and RECORD-LAYER-WRITE-FRAGMENTED
;;; still encrypt straight to the stream, which is what every existing caller
;;; does and what the Gray stream needs.

(defun record-layer-output-pending-p (layer)
  "True while LAYER still owes the transport octets from an earlier submission."
  (declare (type record-layer layer))
  (or (and (record-layer-out-record layer) t)
      (< (record-layer-out-start layer) (record-layer-out-end layer))))

(defun record-layer-output-remaining (layer)
  "How many octets LAYER has still to hand out for the current submission.

   This is a diagnostic total rather than a wire count: the part of it that is
   already framed is ciphertext, and the rest is plaintext that has not been cut
   into records yet, so encryption and padding will change what the second part
   finally weighs."
  (declare (type record-layer layer))
  (+ (let ((record (record-layer-out-record layer)))
       (if record
           (- (length record) (record-layer-out-record-sent layer))
           0))
     (- (record-layer-out-end layer) (record-layer-out-start layer))))

(defun record-layer-submit-plaintext (layer content-type data
                                      &key (start 0) (end (length data)))
  "Stage DATA[start,end) to go out as records of CONTENT-TYPE.  Returns how many
   octets were staged.

   The layer keeps a reference to DATA and cuts records from it as the transport
   takes them, so the caller must leave those octets alone until the layer has
   drained.  Nothing is encrypted here.  The first fragment is produced by
   RECORD-LAYER-PENDING-OUTPUT and not before, so a submission that is never
   asked for costs no sequence number.

   Signals TLS-OUTPUT-IN-FLIGHT rather than replacing a submission that has not
   finished draining.  Replacing one would drop octets the peer is already owed,
   in the middle of a record it has started receiving, and the layer has no way
   to tell the peer that the rest is not coming.

   An empty span stages nothing and produces no record."
  (declare (type record-layer layer)
           (type octet-vector data))
  (unless (<= 0 start end (length data))
    (error "record-layer-submit-plaintext: [~D,~D) lies outside a buffer of ~D octets."
           start end (length data)))
  (when (record-layer-output-pending-p layer)
    (error 'tls-output-in-flight
           :content-type (record-layer-out-content-type layer)
           :outstanding (record-layer-output-remaining layer)))
  (setf (record-layer-out-source layer) data
        (record-layer-out-start layer) start
        (record-layer-out-end layer) end
        (record-layer-out-content-type layer) content-type)
  (- end start))

(defun record-layer-frame-next-record (layer)
  "Cut the next fragment out of LAYER's submission and frame it as one whole
   wire record, header and body together.  Returns the record, or NIL once the
   submission is spent.

   This is the one place on this path where the write cipher's sequence number
   advances, and it advances once per record.  Everything downstream works from
   the octets returned here and never encrypts again, which is why anything that
   can refuse the fragment is checked before the cipher is touched: a refusal
   after encryption would have spent a sequence number on a record that never
   goes out, and the peer would count differently from us for the rest of the
   connection."
  (declare (type record-layer layer))
  (let ((source (record-layer-out-source layer))
        (from (record-layer-out-start layer))
        (to (record-layer-out-end layer)))
    (declare (type fixnum from to))
    (when (or (null source) (>= from to))
      ;; Spent.  Release the caller's vector rather than keep an exhausted
      ;; reference to it, so a drained layer holds nothing of theirs.
      (setf (record-layer-out-source layer) nil
            (record-layer-out-start layer) 0
            (record-layer-out-end layer) 0)
      (return-from record-layer-frame-next-record nil))
    (let ((limit (min (record-layer-max-send-fragment layer)
                      (record-layer-max-out-plaintext layer)))
          (content-type (record-layer-out-content-type layer))
          (cipher (record-layer-write-cipher layer)))
      (declare (type fixnum limit))
      (when (< limit 1)
        (error "record-layer-pending-output: a fragment limit of ~D octets can carry nothing."
               limit))
      (let ((stop (min to (+ from limit))))
        (declare (type fixnum stop))
        (multiple-value-bind (body body-start body-end outer-type)
            (if cipher
                (let ((encrypted (tls13-encrypt-record cipher content-type source
                                                       :start from :end stop)))
                  (values encrypted 0 (length encrypted)
                          +content-type-application-data+))
                (values source from stop content-type))
          (let* ((body-length (- body-end body-start))
                 (record (make-octet-vector (+ 5 body-length))))
            (declare (type fixnum body-length))
            (setf (aref record 0) outer-type
                  (aref record 1) (ldb (byte 8 8) +tls-1.2+)
                  (aref record 2) (ldb (byte 8 0) +tls-1.2+)
                  (aref record 3) (ldb (byte 8 8) body-length)
                  (aref record 4) (ldb (byte 8 0) body-length))
            (replace record body :start1 5 :start2 body-start :end2 body-end)
            (setf (record-layer-out-start layer) stop
                  (record-layer-out-record layer) record
                  (record-layer-out-record-sent layer) 0)
            record))))))

(defun record-layer-pending-output (layer)
  "The octets LAYER wants the transport to send, as (VALUES vector start end).

   Returns (VALUES NIL 0 0) when there is nothing to send.  Otherwise the span
   is the unacknowledged tail of one whole wire record, and the caller sends as
   much of it as the transport will take, then says how much that was with
   RECORD-LAYER-ACK-OUTPUT.  Asking again without acknowledging anything returns
   the same span: a record is framed once and then held until it has all gone.

   A fragment is cut and encrypted here only when no record is outstanding and
   the submission still has plaintext left.  Its size is the smaller of
   MAX-SEND-FRAGMENT and the layer's MAX-OUT-PLAINTEXT budget.

   The vector belongs to the layer and its contents must not be modified.  It is
   the only copy of that ciphertext there will ever be, because encryption is
   not repeatable: the sequence number that produced it has already advanced,
   and re-encrypting the fragment to try again either reuses the nonce this
   record spent or burns the next one and leaves the peer counting differently.
   A short write is resumed from these octets or not at all."
  (declare (type record-layer layer))
  (let ((record (or (record-layer-out-record layer)
                    (record-layer-frame-next-record layer))))
    (if (null record)
        (values nil 0 0)
        (values record (record-layer-out-record-sent layer) (length record)))))

(defun record-layer-ack-output (layer count)
  "Tell LAYER that the transport accepted COUNT octets of the span it handed out.
   Returns how many octets of the current record are still outstanding.

   The cursor advances by COUNT, and once the last octet of a record is
   acknowledged the record is released so the next fragment can be framed.
   Until then RECORD-LAYER-PENDING-OUTPUT keeps offering the rest of the same
   ciphertext, continuing from exactly where this left off.

   Signals TLS-OUTPUT-ACK-OVERRUN for a count larger than what was outstanding,
   including any count at all when nothing was.  This cursor is the only thing
   that decides where a resumed record continues from: a count that is too large
   skips ciphertext the peer needs, and one that is too small repeats octets it
   has already had.  Either way the peer sees a record that will not
   authenticate, and it reads as the connection being tampered with rather than
   as a miscounted write."
  (declare (type record-layer layer))
  (check-type count (integer 0))
  (let* ((record (record-layer-out-record layer))
         (sent (record-layer-out-record-sent layer))
         (size (if record (length record) 0))
         (outstanding (- size sent)))
    (declare (type fixnum sent size outstanding))
    (when (> count outstanding)
      (error 'tls-output-ack-overrun
             :content-type (record-layer-out-content-type layer)
             :acknowledged count
             :outstanding outstanding))
    (let ((now (+ sent count)))
      (declare (type fixnum now))
      (cond ((null record) 0)
            ((= now size)
             (setf (record-layer-out-record layer) nil
                   (record-layer-out-record-sent layer) 0)
             0)
            (t
             (setf (record-layer-out-record-sent layer) now)
             (- size now))))))

;;;; Reading records from a transport that hands them over in pieces
;;;
;;; READ-TLS-RECORD waits on a stream and does not come back until it holds a
;;; whole record.  Its place in that record lives on the stack: the running
;;; total inside READ-EXACT-BYTES, and the header, length and body locals of
;;; READ-TLS-RECORD itself.  A read suspended part way through a record
;;; therefore cannot be resumed, because the part already in hand has nowhere
;;; to wait.  The functions below are the other way round.  The caller owns the
;;; socket, reads whatever the transport happens to have, and hands the octets
;;; in; the layer keeps its place between calls, in the inbound cursor slots on
;;; the structure.
;;;
;;; The layer is given no descriptor and asks for none.  There is no call in
;;; here that can block, and none that can discover an end of file, so the
;;; caller is the only party in a position to see the transport close and says
;;; so with RECORD-LAYER-NOTE-TRANSPORT-EOF.  Keeping that separate from the
;;; feed is the point rather than an inconvenience: on a non-blocking transport
;;; "nothing arrived this time round" is the commonest answer there is, and it
;;; is news about the moment, not about whether the peer is finished.
;;; READ-EXACT-BYTES reads no progress as end of file, which is sound for the
;;; blocking stream it serves and would be an invented close here.
;;;
;;; Nothing above changes.  RECORD-LAYER-READ still pulls whole records off a
;;; stream, which is what the Gray stream needs.

(defun record-layer-transport-eof-p (layer)
  "True once the caller has said the transport will deliver no further octets."
  (declare (type record-layer layer))
  (record-layer-in-eof layer))

(defun record-layer-input-pending-p (layer)
  "True while LAYER is part way through a record it has not finished reading."
  (declare (type record-layer layer))
  (not (eq (record-layer-in-phase layer) :idle)))

(defun record-layer-message-available-p (layer)
  "True while LAYER holds a finished record that is not application data."
  (declare (type record-layer layer))
  (and (record-layer-in-message layer) t))

(defun record-layer-inbound-held-p (layer)
  "True while LAYER is holding a finished result that no reader has taken.

   The layer has room for one at a time, so while this is true it consumes no
   ciphertext.  Draining it with RECORD-LAYER-TAKE-PLAINTEXT or
   RECORD-LAYER-TAKE-MESSAGE is what lets the next record through."
  (declare (type record-layer layer))
  (or (plusp (record-layer-plaintext-available layer))
      (record-layer-message-available-p layer)))

(defun record-layer-input-wanted (layer)
  "How many more octets LAYER needs to finish the unit it is on, so a caller
   can size its next read instead of guessing.

   Five while the layer is between records or part way through a header, and
   the remainder of the body once the header has arrived.

   Zero says do not offer anything yet, for one of two reasons: the layer is
   still holding a finished result nobody has taken, or the caller has already
   said the transport is at end of file.  A feed made anyway would consume
   nothing, so this count and the feed agree about what the layer will take."
  (declare (type record-layer layer))
  (cond ((record-layer-in-eof layer) 0)
        ((record-layer-inbound-held-p layer) 0)
        ((eq (record-layer-in-phase layer) :body)
         (- (record-layer-in-length layer)
            (record-layer-in-body-filled layer)))
        (t (- 5 (record-layer-in-header-seen layer)))))

(defun record-layer-begin-inbound-body (layer)
  "Vet the header LAYER has just finished reading and make room for the body it
   declares.

   The checks are the ones READ-TLS-RECORD makes, with the layer's own inbound
   ciphertext budget applied on top of the protocol ceiling, and they run before
   any room is made so nothing is buffered on behalf of a peer that has already
   broken the framing.  The content type range is what rejects an SSLv2 record
   whose first octet has its high bit set, which would otherwise declare a
   length the layer would sit and wait for.

   No alert is written.  This path has no stream to write one to, and the
   caller that owns the socket is the party that can send one.

   A rejection leaves the cursors on the header that caused it, so a caller that
   feeds on regardless meets the same refusal rather than a different fault
   further downstream."
  (declare (type record-layer layer))
  (let ((content-type (record-layer-in-content-type layer))
        (length (record-layer-in-length layer))
        (limit (min (record-layer-max-in-ciphertext layer)
                    +max-record-size-with-padding+)))
    (declare (type fixnum content-type length limit))
    (unless (and (>= content-type +content-type-change-cipher-spec+)
                 (<= content-type 24))
      (error 'tls-decode-error
             :message (format nil ":WRONG_VERSION_NUMBER: Invalid content type ~D (not a valid TLS record)"
                              content-type)))
    (when (> length limit)
      (error 'tls-record-overflow :size length :max-size limit))
    ;; Reuse the previous body only when it is exactly the size wanted.  What
    ;; goes to the cipher has to be the record and nothing else, so an
    ;; over-large buffer would have to be trimmed into a fresh one anyway.
    (let ((body (record-layer-in-body layer)))
      (unless (and body (= (length body) length))
        (setf (record-layer-in-body layer) (make-octet-vector length))))
    (setf (record-layer-in-body-filled layer) 0
          (record-layer-in-phase layer) :body)))

(defun record-layer-hold-inbound (layer content-type plaintext)
  "Put the finished PLAINTEXT of one record where a reader will look for it.

   Application data joins the plaintext RECORD-LAYER-TAKE-PLAINTEXT serves, so a
   reader takes octets and never has to know how many records they arrived in.
   Anything else is kept whole and apart for RECORD-LAYER-TAKE-MESSAGE.  An
   application-data record carrying nothing is dropped rather than held: it
   delivers no octets, and holding an empty vector would stall the feed until
   somebody took a payload that does not exist.

   The layer's inbound plaintext budget is applied here, which is the first
   point at which the size is known."
  (declare (type record-layer layer)
           (type fixnum content-type)
           (type octet-vector plaintext))
  (let ((limit (min (record-layer-max-in-plaintext layer) +max-record-size+)))
    (declare (type fixnum limit))
    (when (> (length plaintext) limit)
      (error 'tls-record-overflow :size (length plaintext) :max-size limit)))
  (cond ((/= content-type +content-type-application-data+)
         (setf (record-layer-in-message layer) plaintext
               (record-layer-in-message-content-type layer) content-type))
        ((plusp (length plaintext))
         (setf (record-layer-in-plaintext layer) plaintext
               (record-layer-in-plaintext-start layer) 0)))
  content-type)

(defun record-layer-complete-inbound-record (layer)
  "Turn the record LAYER has just finished reading into a result a reader can
   take, and put the inbound cursors back to idle for the next one.

   Decryption is the same one RECORD-LAYER-READ performs, reached the same way
   and happening once for this record.

   The cursors go idle before anything that can signal, so a record the layer
   refuses leaves it between records rather than stuck part way through one.
   IN-BODY is kept, because the next record of the same size can reuse it."
  (declare (type record-layer layer))
  (let ((content-type (record-layer-in-content-type layer))
        (version (record-layer-in-version layer))
        (length (record-layer-in-length layer))
        (body (record-layer-in-body layer))
        (cipher (record-layer-read-cipher layer)))
    (declare (type fixnum content-type version length))
    (setf (record-layer-in-phase layer) :idle
          (record-layer-in-header layer) 0
          (record-layer-in-header-seen layer) 0
          (record-layer-in-body-filled layer) 0)
    (flet ((fragment ()
             ;; The body buffer stays with the layer and is written over by the
             ;; next record, so what leaves here is a copy.
             (let ((copy (make-octet-vector length)))
               (replace copy body :end2 length)
               copy)))
      (cond
        ;; change_cipher_spec means nothing in TLS 1.3 and is not encrypted,
        ;; but middleboxes still expect to see it, so peers still send it.  The
        ;; count is what stops an endless stream of them.
        ((= content-type +content-type-change-cipher-spec+)
         (incf (record-layer-ccs-count layer))
         (when (> (record-layer-ccs-count layer) +max-ccs-messages+)
           (error 'tls-handshake-error
                  :message ":TOO_MANY_EMPTY_FRAGMENTS: Too many change_cipher_spec messages"))
         (record-layer-hold-inbound layer content-type (fragment)))
        (cipher
         ;; RFC 8446 Section 5.1: once keys are installed every record except
         ;; change_cipher_spec arrives wrapped as application_data.
         (unless (= content-type +content-type-application-data+)
           (error 'tls-handshake-error
                  :message (format nil ":INVALID_OUTER_RECORD_TYPE: Expected encrypted record (23), got ~D"
                                   content-type)))
         (let ((header (make-array 5 :element-type '(unsigned-byte 8)
                                     :initial-element 0)))
           (declare (type (simple-array (unsigned-byte 8) (5)) header)
                    (dynamic-extent header))
           ;; The AAD is the header as it arrived, legacy version included, so
           ;; it has to be rebuilt from what was received rather than from what
           ;; a sender would have written.
           (setf (aref header 0) content-type
                 (aref header 1) (ldb (byte 8 8) version)
                 (aref header 2) (ldb (byte 8 0) version)
                 (aref header 3) (ldb (byte 8 8) length)
                 (aref header 4) (ldb (byte 8 0) length))
           (with-buffer-context (*buffer-pool*)
             (multiple-value-bind (plaintext inner-content-type)
                 (tls13-decrypt-record cipher body header)
               (record-layer-hold-inbound layer inner-content-type plaintext)))))
        (t
         (record-layer-hold-inbound layer content-type (fragment)))))))

(defun record-layer-feed-ciphertext (layer data &key (start 0) (end (length data)))
  "Hand LAYER the ciphertext octets DATA[start,end) exactly as they came off the
   transport.  Returns how many of them it took.

   Taking fewer than offered is ordinary and the caller re-offers the rest.  The
   layer stops at the end of a record, so a hand-over spanning a boundary is
   consumed as far as that boundary and no further; it also takes nothing at all
   while it is still holding a finished result, which is how it asks the caller
   to slow down rather than losing a record.  RECORD-LAYER-INPUT-WANTED says
   which of those the caller is looking at before it bothers to read.

   Octets go into the header until five have arrived, then into the body for as
   many as the header declared, and the layer resumes at that exact point on the
   next call however the hand-overs happen to be cut.  A record fed one octet at
   a time and the same record fed whole produce the same result.

   Finishing a record decrypts it and leaves the plaintext for
   RECORD-LAYER-TAKE-PLAINTEXT or, when it is not application data,
   RECORD-LAYER-TAKE-MESSAGE.

   An empty hand-over is not an end of file.  It says the transport had nothing
   this time round, takes nothing, and changes nothing; only
   RECORD-LAYER-NOTE-TRANSPORT-EOF says the peer is finished.  Offering octets
   after that has been said is a caller error, because there is no way for them
   to have arrived."
  (declare (type record-layer layer)
           (type octet-vector data))
  (unless (<= 0 start end (length data))
    (error "record-layer-feed-ciphertext: [~D,~D) lies outside a buffer of ~D octets."
           start end (length data)))
  (when (and (record-layer-in-eof layer) (< start end))
    (error "record-layer-feed-ciphertext: ~D octet~:P offered after the transport was declared closed."
           (- end start)))
  (if (record-layer-inbound-held-p layer)
      0
      (let ((from start))
        (declare (type fixnum from))
        (when (eq (record-layer-in-phase layer) :idle)
          (setf (record-layer-in-phase layer) :header
                (record-layer-in-header layer) 0
                (record-layer-in-header-seen layer) 0))
        (when (eq (record-layer-in-phase layer) :header)
          ;; Each octet is placed at the bit position it occupies in the packed
          ;; header, rather than shifted in from the right, so the content type
          ;; and the legacy version can be read off a header that is not
          ;; complete yet.
          (loop while (and (< from end)
                           (< (record-layer-in-header-seen layer) 5))
                do (let ((seen (record-layer-in-header-seen layer)))
                     (declare (type fixnum seen))
                     (setf (record-layer-in-header layer)
                           (logior (record-layer-in-header layer)
                                   (ash (aref data from) (* 8 (- 4 seen))))
                           (record-layer-in-header-seen layer) (1+ seen))
                     (incf from)))
          (when (= 5 (record-layer-in-header-seen layer))
            (record-layer-begin-inbound-body layer)))
        (when (eq (record-layer-in-phase layer) :body)
          (let* ((filled (record-layer-in-body-filled layer))
                 (length (record-layer-in-length layer))
                 (take (min (- length filled) (- end from))))
            (declare (type fixnum filled length take))
            (when (plusp take)
              (replace (record-layer-in-body layer) data
                       :start1 filled :end1 (+ filled take)
                       :start2 from :end2 (+ from take))
              (setf (record-layer-in-body-filled layer) (+ filled take))
              (incf from take))
            (when (= (record-layer-in-body-filled layer) length)
              (record-layer-complete-inbound-record layer))))
        (- from start))))

(defun record-layer-take-message (layer)
  "The finished record LAYER is holding that is not application data, as
   (VALUES content-type plaintext), or (VALUES NIL NIL) when it holds none.

   Alerts and post-handshake messages such as NewSessionTicket and KeyUpdate
   still arrive during the data phase, and they come out here rather than in the
   application's byte stream, where nothing downstream could tell them from
   payload.  The content type is the inner one for a record that was encrypted.

   Taking the record releases it and lets the feed run again.  Until it is taken
   RECORD-LAYER-FEED-CIPHERTEXT consumes nothing: the layer holds one finished
   record at a time, and making room by overwriting would drop an alert the
   caller had not seen yet."
  (declare (type record-layer layer))
  (let ((message (record-layer-in-message layer)))
    (if (null message)
        (values nil nil)
        (let ((content-type (record-layer-in-message-content-type layer)))
          (declare (type fixnum content-type))
          (setf (record-layer-in-message layer) nil
                (record-layer-in-message-content-type layer) 0)
          (values content-type message)))))

(defun record-layer-note-transport-eof (layer)
  "Tell LAYER that the transport is closed and no further octets can arrive.

   This is the only way the layer can learn it, and it is deliberately not
   something a feed can express.  A feed of zero octets says the transport had
   nothing to give this time round, which on a non-blocking transport is the
   commonest answer there is and says nothing about whether the peer is
   finished.  Reading the two as the same thing is what READ-EXACT-BYTES does,
   correctly, because on a blocking stream a read that makes no progress has
   already waited; here nothing has waited for anything.

   At a record boundary the close is just the end of the octet stream and this
   returns.  Whether the peer ended things properly is a question about
   close_notify and is settled above the record layer.  Part way through a
   record it is a truncation and TLS-DECODE-ERROR is signalled, naming what the
   record still needed.  The flag is set before that, so a caller that handles
   the error still finds a layer that knows the transport is gone."
  (declare (type record-layer layer))
  (setf (record-layer-in-eof layer) t)
  (when (record-layer-input-pending-p layer)
    (let ((body-phase (eq (record-layer-in-phase layer) :body)))
      (error 'tls-decode-error
             :message (format nil "Truncated record: transport closed with ~D octet~:P of the ~A outstanding"
                              (if body-phase
                                  (- (record-layer-in-length layer)
                                     (record-layer-in-body-filled layer))
                                  (- 5 (record-layer-in-header-seen layer)))
                              (if body-phase "body" "header")))))
  (values))

;;;; Alert Processing

(defun process-alert (content &optional record-layer)
  "Process an alert record and signal appropriate condition.
   RECORD-LAYER, if provided, is used to send response alerts before erroring."
  (when (< (length content) 2)
    ;; Send decode_error alert for malformed alerts
    (when record-layer
      (handler-case
          (record-layer-write-alert record-layer +alert-level-fatal+ +alert-decode-error+)
        (error () nil)))
    (error 'tls-error :message ":BAD_ALERT: Alert too short"))
  ;; An alert record must be exactly 2 bytes - reject "double alerts"
  (when (> (length content) 2)
    (when record-layer
      (handler-case
          (record-layer-write-alert record-layer +alert-level-fatal+ +alert-decode-error+)
        (error () nil)))
    (error 'tls-error :message ":BAD_ALERT: Alert record too long"))
  (let ((level (aref content 0))
        (description (aref content 1)))
    ;; close_notify is a clean shutdown; respond with our own close_notify if possible
    (when (= description +alert-close-notify+)
      (when record-layer
        (handler-case
            (record-layer-write-alert record-layer +alert-level-warning+ +alert-close-notify+)
          (error () nil)))
      (error 'tls-connection-closed :clean t))
    ;; Check for invalid alert level or unknown alert description
    ;; Valid alert levels are 1 (warning) and 2 (fatal)
    (unless (or (= level +alert-level-warning+) (= level +alert-level-fatal+))
      (when record-layer
        (handler-case
            (record-layer-write-alert record-layer +alert-level-fatal+ +alert-illegal-parameter+)
          (error () nil)))
      (error 'tls-error
             :message (format nil ":UNKNOWN_ALERT_TYPE: Unknown alert level ~D" level)))
    ;; Check for unknown alert description - send illegal_parameter
    (unless (known-alert-description-p description)
      (when record-layer
        (handler-case
            (record-layer-write-alert record-layer +alert-level-fatal+ +alert-illegal-parameter+)
          (error () nil)))
      (error 'tls-error
             :message (format nil ":UNKNOWN_ALERT_TYPE: Unknown alert type ~D" description)))
    ;; RFC 8446 Section 6: In TLS 1.3, all alerts except close_notify and
    ;; user_canceled MUST be sent at fatal level.
    (when (= level +alert-level-warning+)
      (cond
        ;; user_canceled warning is allowed in TLS 1.3 - ignore it
        ((= description +alert-user-canceled+)
         (return-from process-alert nil))
        ;; All other warning alerts are forbidden in TLS 1.3
        (t
         ;; Send decode_error alert for invalid warning alerts (per BoringSSL expectation)
         (when record-layer
           (handler-case
               (record-layer-write-alert record-layer +alert-level-fatal+ +alert-decode-error+)
             (error () nil)))
         ;; Treat forbidden warning alerts as fatal protocol error
         (error 'tls-error
                :message (format nil ":BAD_ALERT: Invalid warning-level alert in TLS 1.3: ~A"
                                (alert-description-name description))))))
    ;; All other alerts (fatal level) signal an error
    (error 'tls-alert-error :level level :description description)))
