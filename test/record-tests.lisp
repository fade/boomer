;;; test/record-tests.lisp --- TLS record layer tests
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Tests for the TLS 1.3 record layer including framing,
;;; encryption, and padding.

(in-package #:pure-tls/test)

(def-suite record-tests
  :description "Tests for TLS record layer")

(in-suite record-tests)

;;;; Note: hex-to-bytes and bytes-equal are defined in crypto-tests.lisp

;;;; Record Header Tests

(test record-header-format
  "Test TLS record header format"
  ;; TLS 1.3 record header: content_type (1) + legacy_version (2) + length (2)
  (let ((header (make-array 5 :element-type '(unsigned-byte 8)
                              :initial-contents '(23 3 3 0 5))))
    ;; Content type 23 = application_data
    (is (= (aref header 0) 23)
        "Content type should be application_data (23)")
    ;; Legacy version 0x0303 = TLS 1.2
    (is (= (aref header 1) 3) "Legacy version major should be 3")
    (is (= (aref header 2) 3) "Legacy version minor should be 3")
    ;; Length
    (is (= (logior (ash (aref header 3) 8) (aref header 4)) 5)
        "Length should be 5")))

;;;; Content Type Tests

(test content-type-constants
  "Verify content type constants"
  (is (= pure-tls::+content-type-change-cipher-spec+ 20))
  (is (= pure-tls::+content-type-alert+ 21))
  (is (= pure-tls::+content-type-handshake+ 22))
  (is (= pure-tls::+content-type-application-data+ 23)))

;;;; Record Size Limits

(test record-size-constants
  "Verify record size limit constants"
  (is (= pure-tls::+max-record-size+ 16384)
      "Max record size should be 2^14 (16384)")
  (is (= pure-tls::+max-record-size-with-padding+ 16640)
      "Max encrypted record should be 2^14 + 256 (16640) per RFC 8446 §5.4"))

(test full-size-record-roundtrip
  "A record at or near the 16384-byte maximum must encrypt and decrypt
   correctly with both cipher suites.  Regression for the padding-cap term
   in tls13-encrypt-record going negative above content-len 16367, which
   once shrank the inner buffer below the content length."
  (dolist (suite (list pure-tls::+tls-chacha20-poly1305-sha256+
                       pure-tls::+tls-aes-128-gcm-sha256+))
    (dolist (len (list 16367 16368 pure-tls::+max-record-size+))
      (let* ((key (pure-tls::make-octet-vector 32))
             (iv (pure-tls::make-octet-vector 12))
             (enc (pure-tls::make-aead suite key iv))
             (dec (pure-tls::make-aead suite key iv))
             (pt (pure-tls::make-octet-vector len)))
        (dotimes (i len) (setf (aref pt i) (mod i 251)))
        (let* ((rec (pure-tls::tls13-encrypt-record enc 23 pt))
               (hdr (pure-tls::octet-vector 23 3 3
                                            (ldb (byte 8 8) (length rec))
                                            (ldb (byte 8 0) (length rec)))))
          (multiple-value-bind (out content-type)
              (pure-tls::tls13-decrypt-record dec rec hdr)
            (is (= content-type 23)
                "suite ~4,'0X len ~D: content type survives" suite len)
            (is (equalp out pt)
                "suite ~4,'0X len ~D: plaintext round-trips" suite len)))))))

;;;; AEAD Nonce Construction (RFC 8446 Section 5.3)

(test aead-nonce-construction
  "Test AEAD nonce XOR construction"
  ;; per_record_nonce = sequence_number XOR static_iv
  (let ((static-iv (hex-to-bytes "cf782b88dd83549aadf1e984"))
        (sequence-0 (hex-to-bytes "000000000000000000000000"))
        (sequence-1 (hex-to-bytes "000000000000000000000001")))
    ;; Sequence 0: nonce should equal static IV
    (let ((nonce-0 (map '(vector (unsigned-byte 8)) #'logxor static-iv sequence-0)))
      (is (bytes-equal nonce-0 static-iv)
          "Nonce for sequence 0 should equal static IV"))
    ;; Sequence 1: last byte should be XORed
    (let ((nonce-1 (map '(vector (unsigned-byte 8)) #'logxor static-iv sequence-1)))
      (is (= (aref nonce-1 11) (logxor (aref static-iv 11) 1))
          "Nonce for sequence 1 should have last byte XORed with 1"))))

;;;; TLS 1.3 Inner Plaintext Format

(test inner-plaintext-format
  "Test TLS 1.3 inner plaintext structure"
  ;; TLSInnerPlaintext = content + ContentType + zeros (padding)
  (let* ((content (flexi-streams:string-to-octets "Hello" :external-format :utf-8))
         (content-type 23)  ; application_data
         (padding-length 3)
         (inner-length (+ (length content) 1 padding-length))
         (inner (make-array inner-length :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
    ;; Fill content
    (replace inner content)
    ;; Set content type byte
    (setf (aref inner (length content)) content-type)
    ;; Padding is zeros (already initialized)

    (is (= (length inner) 9)
        "Inner plaintext length should be content + type + padding")
    (is (= (aref inner 5) 23)
        "Content type byte should be at position after content")
    (is (zerop (aref inner 8))
        "Padding bytes should be zero")))

;;;; Record Padding Policy Tests

(test record-padding-policy-nil
  "Test no padding policy"
  (let ((pure-tls:*record-padding-policy* nil))
    ;; With nil policy, no extra padding should be added
    (is (null pure-tls:*record-padding-policy*)
        "Nil padding policy should be nil")))

(test record-padding-policy-block
  "Test block padding policy"
  (let ((pure-tls:*record-padding-policy* :block-256))
    (is (eql pure-tls:*record-padding-policy* :block-256)
        "Block-256 padding policy should be set")))

;;;; Alert Record Tests

(test alert-level-constants
  "Verify alert level constants"
  (is (= pure-tls::+alert-level-warning+ 1))
  (is (= pure-tls::+alert-level-fatal+ 2)))

(test alert-description-constants
  "Verify important alert description constants"
  (is (zerop pure-tls:+alert-close-notify+))
  (is (= pure-tls:+alert-unexpected-message+ 10))
  (is (= pure-tls:+alert-bad-record-mac+ 20))
  (is (= pure-tls:+alert-handshake-failure+ 40))
  (is (= pure-tls:+alert-bad-certificate+ 42))
  (is (= pure-tls:+alert-certificate-expired+ 45))
  (is (= pure-tls:+alert-unknown-ca+ 48))
  (is (= pure-tls:+alert-decode-error+ 50)))

;;;; Handshake Record Tests

(test handshake-type-constants
  "Verify handshake message type constants"
  (is (= pure-tls::+handshake-client-hello+ 1))
  (is (= pure-tls::+handshake-server-hello+ 2))
  (is (= pure-tls::+handshake-new-session-ticket+ 4))
  (is (= pure-tls::+handshake-encrypted-extensions+ 8))
  (is (= pure-tls::+handshake-certificate+ 11))
  (is (= pure-tls::+handshake-certificate-request+ 13))
  (is (= pure-tls::+handshake-certificate-verify+ 15))
  (is (= pure-tls::+handshake-finished+ 20))
  (is (= pure-tls::+handshake-key-update+ 24)))

;;;; Test Runner

;;;; Handing a finished connection to an adopted record layer

;;; Nothing below encrypts or decrypts anything.  The AEAD ciphers exist only so
;;; the handover has live ones to carry across, and no sequence number is ever
;;; advanced or read.

(defun handover-cipher (fill)
  "An AEAD cipher with distinctive key and IV octets, for identity only."
  (pure-tls::make-aead pure-tls:+tls-aes-128-gcm-sha256+
                       (pure-tls::make-octet-vector 16 :initial-element fill)
                       (pure-tls::make-octet-vector 12 :initial-element (1+ fill))))

(defun make-handover-stream (payload consumed
                             &optional (transport
                                        (flexi-streams:make-in-memory-output-stream)))
  "A blocking TLS stream holding PAYLOAD as decrypted input, of which the
   application has already read the first CONSUMED octets.  The prefix is read
   through the ordinary blocking path so the input position ends up where a real
   application would have left it.

   TRANSPORT is what the stream and, after a handover, the record layer write
   to; a caller passes one in when what it needs to watch is the transport."
  (let* ((stream (make-instance 'pure-tls::tls-client-stream :stream transport))
         (layer (pure-tls::make-record-layer transport)))
    (setf (pure-tls::record-layer-read-cipher layer) (handover-cipher 1)
          (pure-tls::record-layer-write-cipher layer) (handover-cipher 3)
          (pure-tls::record-layer-cipher-suite layer) pure-tls:+tls-aes-128-gcm-sha256+)
    (setf (pure-tls::tls-stream-record-layer stream) layer
          (pure-tls::tls-stream-input-buffer stream) (copy-seq payload)
          (pure-tls::tls-stream-input-position stream) 0)
    (dotimes (i consumed) (read-byte stream))
    stream))

(defun handover-drain (layer)
  "Everything LAYER is currently holding as inbound plaintext, as one vector."
  (let ((out (pure-tls::make-octet-vector
              (pure-tls::record-layer-plaintext-available layer))))
    (pure-tls::record-layer-take-plaintext layer out)
    out))

(test handover-moves-unread-plaintext-to-record-layer
  "Adoption carries the unread tail of the stream's input buffer and no more."
  (let* ((payload (pure-tls::octet-vector 10 11 12 13 14 15 16 17))
         (consumed 3)
         (tail (subseq payload consumed))
         (stream (make-handover-stream payload consumed)))
    (is (= (- (length payload) consumed)
           (pure-tls::tls-stream-buffer-remaining stream))
        "The fixture should leave exactly the tail unread on the stream")
    (let ((layer (pure-tls::adopt-record-layer-from-tls-stream stream)))
      (is (zerop (pure-tls::tls-stream-buffer-remaining stream))
          "The stream should hold no inbound plaintext once it has been moved")
      (is (= (length tail) (pure-tls::record-layer-plaintext-available layer))
          "The layer should hold exactly the octets the application had not read")
      ;; Take the tail in two bites so the cursor has to advance between them.
      (let ((out (pure-tls::make-octet-vector (length tail))))
        (is (= 2 (pure-tls::record-layer-take-plaintext layer out :end 2))
            "A bounded take should write only as many octets as it was given room for")
        (is (= (- (length tail) 2)
               (pure-tls::record-layer-plaintext-available layer))
            "The cursor should advance past what was taken")
        (is (= (- (length tail) 2)
               (pure-tls::record-layer-take-plaintext layer out :start 2))
            "The rest of the tail should follow")
        (is (equalp tail out)
            "Octets should arrive in order, none lost and none repeated")
        (is (zerop (pure-tls::record-layer-plaintext-available layer))
            "The layer should be empty once the tail has been taken")
        (is (null (pure-tls::record-layer-in-plaintext layer))
            "A drained layer should release the vector rather than hold an empty one")
        (is (zerop (pure-tls::record-layer-take-plaintext layer out))
            "A drained layer should yield nothing rather than repeat itself")))))

(test handover-tail-check-rejects-both-mistakes
  "The tail comparison tells a correct handover from either way of botching it.
   Dropping the leftover loses the tail; carrying the whole input buffer across
   replays octets the application already read.  Both are checked here against
   the same comparison the test above passes, so passing it means something."
  (let* ((payload (pure-tls::octet-vector 10 11 12 13 14 15 16 17))
         (consumed 3)
         (tail (subseq payload consumed)))
    (flet ((adopted (&rest keys)
             (apply #'pure-tls::adopt-record-layer
                    (flexi-streams:make-in-memory-output-stream)
                    :read-cipher (handover-cipher 1)
                    :write-cipher (handover-cipher 3)
                    keys)))
      (let ((dropped (handover-drain (adopted :in-plaintext nil))))
        (is (not (equalp tail dropped))
            "Dropping the leftover should not satisfy the tail check")
        (is (zerop (length dropped))
            "Dropping the leftover loses every octet the application had not read"))
      (let ((whole (handover-drain (adopted :in-plaintext payload
                                            :in-plaintext-start 0))))
        (is (not (equalp tail whole))
            "Carrying the whole input buffer should not satisfy the tail check")
        (is (equalp payload whole)
            "Carrying the whole input buffer replays the already-read prefix"))
      (let ((moved (handover-drain (adopted :in-plaintext payload
                                            :in-plaintext-start consumed))))
        (is (equalp tail moved)
            "Only the tail from the input position satisfies the check")))))

;;;; Reading a record while plaintext is still held

(defun record-octets (content-type body)
  "One whole TLS record as it appears on the wire: five header octets and BODY."
  (let ((wire (pure-tls::make-octet-vector (+ 5 (length body)))))
    (setf (aref wire 0) content-type
          (aref wire 1) 3
          (aref wire 2) 3
          (aref wire 3) (ldb (byte 8 8) (length body))
          (aref wire 4) (ldb (byte 8 0) (length body)))
    (replace wire body :start1 5)
    wire))

(defun record-on-the-wire (content-type body)
  "An input stream carrying one whole unencrypted TLS record."
  (flexi-streams:make-in-memory-input-stream (record-octets content-type body)))

(test record-read-refuses-a-record-while-plaintext-is-held
  "Asking for a record while the layer still holds decrypted octets is refused.

   A caller drains what the layer is holding before it asks the transport for
   more.  Forgetting to used to cost nothing visible: it reorders the stream,
   and the octets arrive looking like the peer sent them that way round, which
   is not something the caller can debug from what it sees.  Both directions of
   the refusal are checked here, because a guard nobody
   has watched go red is not a guard: a layer holding nothing reads through as
   it always has, and a layer holding something refuses and keeps the record for
   afterwards."
  (let ((body (pure-tls::octet-vector 1 2 3)))
    ;; Holding nothing: the read goes through to the transport.
    (let ((layer (pure-tls::make-record-layer
                  (record-on-the-wire pure-tls::+content-type-handshake+ body))))
      (multiple-value-bind (content-type fragment) (pure-tls::record-layer-read layer)
        (is (= pure-tls::+content-type-handshake+ content-type)
            "A layer holding no plaintext should read the record it was sent")
        (is (equalp body fragment)
            "and hand back the octets that record carried")))
    ;; Holding something: the same call refuses, and says how much is waiting.
    (let ((layer (pure-tls::make-record-layer
                  (record-on-the-wire pure-tls::+content-type-handshake+ body)))
          (held (pure-tls::octet-vector 9 9)))
      (setf (pure-tls::record-layer-in-plaintext layer) held)
      (signals pure-tls::tls-plaintext-pending
        (pure-tls::record-layer-read layer))
      (is (= 2 (handler-case (progn (pure-tls::record-layer-read layer) nil)
                 (pure-tls::tls-plaintext-pending (condition)
                   (pure-tls::tls-plaintext-pending-available condition))))
          "The refusal should be specific enough to handle on its own and should
           name how many octets are waiting")
      (let ((sink (pure-tls::make-octet-vector 2)))
        (pure-tls::record-layer-take-plaintext layer sink)
        (is (equalp held sink)
            "The held octets should come out first, which is the ordering the
             refusal exists to keep"))
      (multiple-value-bind (content-type fragment) (pure-tls::record-layer-read layer)
        (is (= pure-tls::+content-type-handshake+ content-type)
            "The record was held back rather than lost")
        (is (equalp body fragment)
            "and arrives intact once the plaintext in front of it is taken")))))

;;;; Handing records to a transport that takes them a few octets at a time

;;; Nothing below decrypts anything, and nothing builds a second cipher from the
;;; same key and IV.  Each record's ciphertext is produced exactly once; what is
;;; checked is that the same octets come back out of the layer afterwards.

(defun outbound-cipher ()
  "A live AEAD cipher for the outbound tests.  Key and IV are fixed so runs are
   reproducible; nothing here decrypts, so no peer needs them."
  (pure-tls::make-aead pure-tls:+tls-aes-128-gcm-sha256+
                       (pure-tls::make-octet-vector 16 :initial-element 7)
                       (pure-tls::make-octet-vector 12 :initial-element 9)))

(defun outbound-layer (cipher &key (max-send-fragment 16))
  "A record layer with no stream at all.  Passing NIL where the stream goes is
   part of the point: this path hands out octets and must never reach for a
   transport of its own."
  (let ((layer (pure-tls::make-record-layer nil :max-send-fragment max-send-fragment)))
    (setf (pure-tls::record-layer-write-cipher layer) cipher
          (pure-tls::record-layer-cipher-suite layer) pure-tls:+tls-aes-128-gcm-sha256+)
    layer))

(defun counting-payload (size)
  "SIZE octets that all differ from their neighbours, so a span taken from the
   wrong place is visible rather than plausible."
  (let ((payload (pure-tls::make-octet-vector size)))
    (dotimes (i size payload)
      (setf (aref payload i) (mod i 251)))))

(defun outbound-sequence-number (layer)
  "How many records LAYER's write cipher has encrypted."
  (pure-tls::aead-cipher-sequence-number (pure-tls::record-layer-write-cipher layer)))

(defun drain-outbound (layer accept)
  "Run LAYER's outbound path to exhaustion against a transport that takes at
   most ACCEPT octets each time round.  Returns every octet the transport
   received, in order, and the list of records the layer framed."
  (let ((received (make-array 0 :element-type '(unsigned-byte 8)
                                :adjustable t :fill-pointer 0))
        (records '()))
    (loop
      (multiple-value-bind (record start end) (pure-tls::record-layer-pending-output layer)
        (when (null record)
          (return))
        (unless (eq record (first records))
          (push record records))
        (let ((taken (min accept (- end start))))
          (loop for i from start below (+ start taken)
                do (vector-push-extend (aref record i) received))
          (pure-tls::record-layer-ack-output layer taken))))
    (values (coerce received '(simple-array (unsigned-byte 8) (*)))
            (nreverse records))))

(test outbound-record-resumes-from-the-ciphertext-it-already-produced
  "A part-sent record continues octet for octet out of the ciphertext already
   framed, and the write sequence number advances exactly once for that record.

   Resuming any other way means encrypting the fragment a second time.  That
   either reuses the nonce the first attempt spent, which costs confidentiality
   outright rather than just the connection, or spends the next one and leaves
   the peer counting behind us.  Nothing here encrypts a fragment twice: what is
   shown is that the span offered after a partial acknowledgement is the tail of
   the same vector, and that the counter stands still while it is handed out."
  (let* ((cipher (outbound-cipher))
         (layer (outbound-layer cipher :max-send-fragment 16))
         (payload (counting-payload 16)))
    (is (null (pure-tls::record-layer-stream layer))
        "This path works for a caller that has no stream to give the layer")
    (is (zerop (outbound-sequence-number layer))
        "A fresh cipher has spent no sequence number yet")
    (is (= 16 (pure-tls::record-layer-submit-plaintext
               layer pure-tls::+content-type-application-data+ payload))
        "Submitting should stage every octet it was given")
    (is (zerop (outbound-sequence-number layer))
        "Submitting stages plaintext and encrypts nothing")
    (multiple-value-bind (record start end) (pure-tls::record-layer-pending-output layer)
      (is (not (null record))
          "The layer should offer the record it framed")
      (is (= 0 start)
          "A freshly framed record starts at its first octet")
      (is (= (length record) end)
          "and runs to its last")
      (is (= 1 (outbound-sequence-number layer))
          "Framing one record costs exactly one sequence number")
      (is (= pure-tls::+content-type-application-data+ (aref record 0))
          "An encrypted record goes out under the application_data outer type")
      (is (= (- end 5) (+ (ash (aref record 3) 8) (aref record 4)))
          "and its header declares the body length that follows it")
      (let ((framed (copy-seq record)))
        ;; The transport takes seven octets this time round and no more.
        (is (= (- end 7) (pure-tls::record-layer-ack-output layer 7))
            "The rest of the record should still be outstanding")
        (is (= 1 (outbound-sequence-number layer))
            "Acknowledging part of a record must not encrypt anything")
        (multiple-value-bind (again from to) (pure-tls::record-layer-pending-output layer)
          (is (eq record again)
              "The resumed record should be the very vector already produced")
          (is (= 7 from)
              "and should pick up where the transport stopped, not start again")
          (is (= end to)
              "and still end where it ended")
          (is (= 1 (outbound-sequence-number layer))
              "Resuming must not advance the write sequence number")
          (is (equalp (subseq framed 7) (subseq again from to))
              "The resumed span should continue the same ciphertext"))
        ;; Finish the record, then check what the transport saw end to end.
        (let ((received (concatenate '(vector (unsigned-byte 8))
                                     (subseq framed 0 7)
                                     (drain-outbound layer 5))))
          (is (equalp framed received)
              "Across the short writes the transport should receive the record
               exactly once, in order, with nothing repeated and nothing skipped")
          (is (= 1 (outbound-sequence-number layer))
              "and the whole record should have cost one sequence number")
          (is (not (pure-tls::record-layer-output-pending-p layer))
              "A fully acknowledged submission leaves nothing pending")
          (is (null (pure-tls::record-layer-out-source layer))
              "and the layer lets go of the caller's buffer"))))))

(test outbound-submission-is-fragmented-one-record-per-sequence-number
  "A submission larger than the fragment limit goes out as several records, each
   costing one sequence number, and a stingy transport receives all of them
   whole and in order."
  (let* ((cipher (outbound-cipher))
         (layer (outbound-layer cipher :max-send-fragment 16))
         (payload (counting-payload 40)))
    (pure-tls::record-layer-submit-plaintext
     layer pure-tls::+content-type-application-data+ payload)
    (multiple-value-bind (received records) (drain-outbound layer 3)
      (is (= 3 (length records))
          "Forty octets at sixteen to a record makes three records")
      (is (= 3 (outbound-sequence-number layer))
          "and three records cost three sequence numbers, one each")
      (dolist (record records)
        (is (= pure-tls::+content-type-application-data+ (aref record 0))
            "Every encrypted record goes out under the application_data type")
        (is (= (- (length record) 5) (+ (ash (aref record 3) 8) (aref record 4)))
            "and declares the body length that follows its header"))
      (is (equalp (apply #'concatenate '(vector (unsigned-byte 8)) records)
                  received)
          "The transport should receive exactly the records the layer framed")
      (is (not (pure-tls::record-layer-output-pending-p layer))
          "and the layer should be idle once they have all been acknowledged"))))

(test outbound-submit-refuses-to-replace-a-draining-submission
  "A second submission is refused while the first is still draining, at both
   points where one could turn up: before any record has been framed, and with a
   record half way out to the transport.  Taking it would drop octets the peer
   is already owed, in the middle of a record it has begun receiving, and the
   layer has no way to tell the peer that the rest is not coming."
  (let* ((cipher (outbound-cipher))
         (layer (outbound-layer cipher :max-send-fragment 16))
         (staged (counting-payload 40))
         (other (counting-payload 8)))
    (is (= 40 (pure-tls::record-layer-submit-plaintext
               layer pure-tls::+content-type-application-data+ staged)))
    (signals pure-tls::tls-output-in-flight
      (pure-tls::record-layer-submit-plaintext
       layer pure-tls::+content-type-application-data+ other))
    (let ((acked (multiple-value-bind (record start end)
                     (pure-tls::record-layer-pending-output layer)
                   (declare (ignore record start))
                   (let ((half (floor end 2)))
                     (is (plusp (pure-tls::record-layer-ack-output layer half))
                         "Half a record out leaves the other half outstanding")
                     half))))
      (signals pure-tls::tls-output-in-flight
        (pure-tls::record-layer-submit-plaintext
         layer pure-tls::+content-type-application-data+ other))
      (multiple-value-bind (received records) (drain-outbound layer 64)
        (is (= 3 (length records))
            "The refusals should leave the staged submission exactly as it was")
        (is (= 3 (outbound-sequence-number layer))
            "and should cost no extra sequence number")
        (is (= (- (reduce #'+ records :key #'length) acked) (length received))
            "The transport receives the rest of the part-sent record and both of
             the records after it, and nothing twice")))
    (is (= 8 (pure-tls::record-layer-submit-plaintext
              layer pure-tls::+content-type-application-data+ other))
        "A drained layer takes the next submission")))

(test outbound-acknowledgement-past-the-end-of-the-span-is-refused
  "An acknowledgement bigger than what was handed out is refused rather than
   believed, and a refused one leaves the cursor where it was.  This cursor is
   the only thing that decides where a resumed record continues from, so a count
   that runs past the end skips ciphertext the peer needs and one that falls
   short repeats octets it has already had."
  (let* ((cipher (outbound-cipher))
         (layer (outbound-layer cipher :max-send-fragment 16))
         (payload (counting-payload 16)))
    (signals pure-tls::tls-output-ack-overrun
      (pure-tls::record-layer-ack-output layer 1))
    (is (zerop (pure-tls::record-layer-ack-output layer 0))
        "Acknowledging nothing when nothing is outstanding is not an error")
    (signals type-error
      (pure-tls::record-layer-ack-output layer -1))
    (pure-tls::record-layer-submit-plaintext
     layer pure-tls::+content-type-application-data+ payload)
    (multiple-value-bind (record start end) (pure-tls::record-layer-pending-output layer)
      (declare (ignore record start))
      (signals pure-tls::tls-output-ack-overrun
        (pure-tls::record-layer-ack-output layer (1+ end)))
      (is (= end (pure-tls::record-layer-ack-output layer 0))
          "A refused acknowledgement should not have moved the cursor")
      (is (= (- end 4) (pure-tls::record-layer-ack-output layer 4))
          "A count within the span advances it")
      (signals pure-tls::tls-output-ack-overrun
        (pure-tls::record-layer-ack-output layer (- end 3)))
      (is (= (- end 4) (pure-tls::record-layer-ack-output layer 0))
          "and the cursor still stands where the transport left it")
      (multiple-value-bind (again from to) (pure-tls::record-layer-pending-output layer)
        (declare (ignore again to))
        (is (= 4 from)
            "so the record resumes from the last count the layer believed")))))

(test outbound-records-without-a-cipher-carry-their-own-content-type
  "Before keys are installed a framed record goes out in the clear under the
   content type it was submitted with, which is what the handshake needs."
  (let ((layer (pure-tls::make-record-layer nil :max-send-fragment 4))
        (payload (counting-payload 6)))
    (pure-tls::record-layer-submit-plaintext
     layer pure-tls::+content-type-handshake+ payload)
    (multiple-value-bind (received records) (drain-outbound layer 2)
      (is (= 2 (length records))
          "Six octets at four to a record makes two records")
      (dolist (record records)
        (is (= pure-tls::+content-type-handshake+ (aref record 0))
            "An unencrypted record carries the submitted content type itself"))
      (is (equalp payload
                  (concatenate '(vector (unsigned-byte 8))
                               (subseq (first records) 5)
                               (subseq (second records) 5)))
          "and the bodies are the submitted octets, split at the fragment limit")
      (is (= 16 (length received))
          "Two headers and six octets of payload reach the transport"))))

;;;; Taking records from a transport that hands them over in pieces

;;; The layer is handed octets and is never given anything to read from, so
;;; every layer below is built on NIL where the stream goes.

(defun inbound-cipher ()
  "An AEAD cipher for the fed inbound tests.  Two are made from the same key and
   IV, one to produce the fixture records and one for the layer to read them
   with, which is what the two ends of a connection hold.  No nonce encrypts
   twice: each fixture record is encrypted once, by the sender object, and the
   layer's object only ever decrypts."
  (pure-tls::make-aead pure-tls:+tls-aes-128-gcm-sha256+
                       (pure-tls::make-octet-vector 16 :initial-element 5)
                       (pure-tls::make-octet-vector 12 :initial-element 11)))

(defun inbound-layer (&key read-cipher)
  "A record layer with no stream at all, ready to be fed ciphertext."
  (let ((layer (pure-tls::make-record-layer nil)))
    (when read-cipher
      (setf (pure-tls::record-layer-read-cipher layer) read-cipher
            (pure-tls::record-layer-cipher-suite layer)
            pure-tls:+tls-aes-128-gcm-sha256+))
    layer))

(defun feed-record (layer wire chunk)
  "Offer WIRE to LAYER at most CHUNK octets at a time, re-offering whatever it
   declines, and stop as soon as it takes nothing from an offer that had octets
   in it.  Returns how many octets it took altogether."
  (let ((at 0))
    (loop while (< at (length wire))
          do (let ((taken (pure-tls::record-layer-feed-ciphertext
                           layer wire
                           :start at :end (min (length wire) (+ at chunk)))))
               (when (zerop taken) (return))
               (incf at taken)))
    at))

(defun taken-message (layer)
  "The body of the finished record LAYER holds that is not application data, or
   NIL when it holds none."
  (nth-value 1 (pure-tls::record-layer-take-message layer)))

(defun forget-inbound-progress (layer &key (header t) (body t))
  "Throw away what LAYER has read of the record it is part way through, which is
   what a reader whose place lives on the stack loses at every suspension.  The
   controls below use it to show what the inbound cursors are buying."
  (when header
    (setf (pure-tls::record-layer-in-phase layer) :idle
          (pure-tls::record-layer-in-header layer) 0
          (pure-tls::record-layer-in-header-seen layer) 0))
  (when body
    (setf (pure-tls::record-layer-in-body-filled layer) 0))
  layer)

(test inbound-record-fed-one-octet-at-a-time-matches-a-single-feed
  "The same record delivered one octet per call and delivered whole produce the
   same result.  Where the transport happened to cut the octets is not something
   the peer chose, and it must not change what the reader sees.

   The control is the reader this path exists to replace.  Clearing the inbound
   cursors after every octet is what a reader whose place lives on the stack
   loses at each suspension, and the comparison the split feed passes rejects
   it: five separate first octets never add up to a header, so nothing arrives
   at all."
  (let* ((body (counting-payload 23))
         (wire (record-octets pure-tls::+content-type-handshake+ body)))
    (let ((layer (inbound-layer)))
      (is (null (pure-tls::record-layer-stream layer))
          "This path serves a caller that has no stream to give the layer")
      (is (= 5 (pure-tls::record-layer-input-wanted layer))
          "An idle layer wants a header before anything else")
      (is (= (length wire) (pure-tls::record-layer-feed-ciphertext layer wire))
          "A whole record offered in one call is taken in one call")
      (is (equalp body (taken-message layer))
          "and its body arrives intact"))
    (let ((layer (inbound-layer)))
      (is (= (length wire) (feed-record layer wire 1))
          "The same record offered an octet at a time is taken an octet at a time")
      (is (not (pure-tls::record-layer-input-pending-p layer))
          "and the layer is between records once the last octet is in")
      (is (equalp body (taken-message layer))
          "and the body is the same as when the record arrived whole"))
    (let ((layer (inbound-layer)))
      (dotimes (i (length wire))
        (pure-tls::record-layer-feed-ciphertext layer wire :start i :end (1+ i))
        (forget-inbound-progress layer))
      (let ((lost (taken-message layer)))
        (is (not (equalp body lost))
            "Losing the cursors between calls should not satisfy the comparison")
        (is (null lost)
            "and it loses the record outright rather than delivering it late")))))

(test inbound-record-split-across-the-header-boundary-resumes
  "A record cut anywhere, the boundary between its header and its body
   included, arrives whole.  That boundary is the case the inbound cursors exist
   for: a header is five octets and a transport has no reason to deliver them
   together, so the part already read has to wait somewhere that outlives the
   call.  Every cut point in the record is tried against the same comparison,
   and the layer is asked at each one how much it still wants, because a caller
   sizing its next read has nothing else to go on.

   The control keeps the header progress and clears the body cursor at the cut,
   which is what a layer that tracked only half its place would do.  The
   comparison rejects it."
  (let* ((body (counting-payload 9))
         (wire (record-octets pure-tls::+content-type-handshake+ body)))
    (loop for cut from 1 below (length wire)
          do (let ((layer (inbound-layer)))
               (is (= cut (pure-tls::record-layer-feed-ciphertext
                           layer wire :start 0 :end cut))
                   "The layer should take the whole of the first piece")
               (is (pure-tls::record-layer-input-pending-p layer)
                   "and should know it is part way through a record")
               (is (= (if (< cut 5) (- 5 cut) (- (length wire) cut))
                      (pure-tls::record-layer-input-wanted layer))
                   "and should say what would finish the unit it is on, which is
                    the header until five octets are in and the body after")
               (is (= (- (length wire) cut)
                      (pure-tls::record-layer-feed-ciphertext
                       layer wire :start cut :end (length wire)))
                   "It should then take the rest")
               (is (equalp body (taken-message layer))
                   "and hand over the record the two pieces make up")))
    (let ((layer (inbound-layer))
          (cut 7))
      (pure-tls::record-layer-feed-ciphertext layer wire :start 0 :end cut)
      (forget-inbound-progress layer :header nil)
      (pure-tls::record-layer-feed-ciphertext layer wire :start cut :end (length wire))
      (is (null (taken-message layer))
          "Losing the body cursor at the cut should not satisfy the comparison"))))

(test inbound-end-of-file-is-told-apart-from-no-octets-right-now
  "A hand-over of no octets and a closed transport are different facts, and the
   layer keeps them apart.

   On a blocking stream they are the same thing, because a read that came back
   with nothing has already waited; READ-EXACT-BYTES is right to end there.
   Nothing waits on this path.  An empty hand-over means only that the transport
   had nothing at that instant, which is the commonest answer a non-blocking
   transport gives, and reading it as a close would end healthy connections at
   random.

   The same two questions are put to the layer in both states, and the last
   block applies the conflation at exactly the point the empty hand-overs
   happened, so the difference is shown rather than asserted."
  (let* ((body (counting-payload 6))
         (wire (record-octets pure-tls::+content-type-handshake+ body))
         (empty (pure-tls::make-octet-vector 0)))
    (let ((layer (inbound-layer)))
      (pure-tls::record-layer-feed-ciphertext layer wire :start 0 :end 3)
      (dotimes (i 4)
        (is (zerop (pure-tls::record-layer-feed-ciphertext layer empty))
            "A hand-over of no octets takes nothing")
        (is (zerop (pure-tls::record-layer-feed-ciphertext layer wire :start 3 :end 3))
            "and an empty span of a full buffer says the same thing"))
      (is (not (pure-tls::record-layer-transport-eof-p layer))
          "None of that says the transport is finished")
      (is (= 2 (pure-tls::record-layer-input-wanted layer))
          "and the layer is still waiting on the rest of the header")
      (pure-tls::record-layer-feed-ciphertext layer wire :start 3 :end (length wire))
      (is (equalp body (taken-message layer))
          "so the record arrives once the octets do"))
    (let ((layer (inbound-layer)))
      (pure-tls::record-layer-feed-ciphertext layer wire :start 0 :end 3)
      (is (not (pure-tls::record-layer-transport-eof-p layer))
          "The same layer, in the same place in the same record")
      (signals pure-tls:tls-decode-error
        (pure-tls::record-layer-note-transport-eof layer))
      (is (pure-tls::record-layer-transport-eof-p layer)
          "now holds the fact the empty hand-overs never established")
      (is (zerop (pure-tls::record-layer-input-wanted layer))
          "The layer asks for nothing more once the transport is gone")
      (signals simple-error
        (pure-tls::record-layer-feed-ciphertext layer wire :start 3 :end (length wire)))
      (is (null (taken-message layer))
          "and a truncated record is not delivered as though it were whole"))
    (let ((layer (inbound-layer)))
      (pure-tls::record-layer-feed-ciphertext layer wire)
      (pure-tls::record-layer-note-transport-eof layer)
      (is (pure-tls::record-layer-transport-eof-p layer)
          "A close between records is noted and is not an error")
      (is (equalp body (taken-message layer))
          "and the record that had already arrived is still there to take"))
    (let ((layer (inbound-layer)))
      (pure-tls::record-layer-feed-ciphertext layer wire :start 0 :end 3)
      (handler-case (pure-tls::record-layer-note-transport-eof layer)
        (pure-tls:tls-decode-error () nil))
      (is (not (equalp body
                       (handler-case
                           (progn (pure-tls::record-layer-feed-ciphertext
                                   layer wire :start 3 :end (length wire))
                                  (taken-message layer))
                         (error () nil))))
          "Treating those empty hand-overs as a close costs the record, which is
           what the two questions above are there to tell apart"))))

(test inbound-records-that-are-not-application-data-stay-out-of-the-byte-stream
  "The data phase still carries alerts and post-handshake messages such as
   NewSessionTicket and KeyUpdate, and those come out separately from the
   application's octets.

   Splicing a ticket into the byte stream would hand the application octets it
   has no way to tell from payload, and the damage would be silent.  What the
   application takes is therefore compared both with the payload and with what
   it would have taken had the ticket been mixed in, so the comparison rejects
   the failure as well as accepting the success.

   This is also where the decrypt path is exercised, one record at a time
   through it.  Nothing is encrypted twice: each fixture record is produced once
   by the sender cipher, and the layer's cipher only decrypts."
  (let* ((sender (inbound-cipher))
         (layer (inbound-layer :read-cipher (inbound-cipher)))
         (payload (counting-payload 12))
         (ticket (pure-tls::octet-vector 4 0 0 3 7 8 9))
         (app-wire (record-octets
                    pure-tls::+content-type-application-data+
                    (pure-tls::tls13-encrypt-record
                     sender pure-tls::+content-type-application-data+ payload)))
         (ticket-wire (record-octets
                       pure-tls::+content-type-application-data+
                       (pure-tls::tls13-encrypt-record
                        sender pure-tls::+content-type-handshake+ ticket))))
    (is (= (length app-wire) (feed-record layer app-wire 1))
        "An encrypted record dribbling in an octet at a time is taken whole")
    (is (= (length payload) (pure-tls::record-layer-plaintext-available layer))
        "and what a reader can take is the decrypted payload")
    (is (not (pure-tls::record-layer-message-available-p layer))
        "Application data is not surfaced as a message")
    (is (zerop (pure-tls::record-layer-feed-ciphertext layer ticket-wire))
        "The layer takes nothing while it still holds a finished result, rather
         than making room by overwriting one")
    (let ((taken (handover-drain layer)))
      (is (equalp payload taken)
          "The application takes the payload the peer sent")
      (is (not (equalp (concatenate '(vector (unsigned-byte 8)) payload ticket)
                       taken))
          "and not the payload with the ticket spliced onto it, which is what
           one plaintext buffer for every content type would have produced"))
    (is (= (length ticket-wire) (feed-record layer ticket-wire 1))
        "With the payload taken the next record goes in")
    (is (zerop (pure-tls::record-layer-plaintext-available layer))
        "It adds nothing to the application's byte stream")
    (is (pure-tls::record-layer-message-available-p layer)
        "and waits as a message instead")
    (multiple-value-bind (content-type message)
        (pure-tls::record-layer-take-message layer)
      (is (= pure-tls::+content-type-handshake+ content-type)
          "reported under the inner content type the record actually carried")
      (is (equalp ticket message)
          "with its octets intact"))
    (is (not (pure-tls::record-layer-message-available-p layer))
        "and taking it leaves the layer ready for the next record")))

;;;; Ownership of the connection after the handover

;;; Adoption passes the stream's AEAD ciphers and its transport across by
;;; reference, so an unmarked stream would go on holding accessors for state it
;;; no longer owns: a further write advances a sequence number the layer is also
;;; advancing, and a close ends a connection that is still in use.  What follows
;;; checks that the stream stops acting on either, and, as the control that
;;; makes those checks mean something, that a stream which has not been through
;;; a handover still does all of it.

(defclass handover-probe-transport
    (trivial-gray-streams:fundamental-binary-output-stream)
  ((sink :initform (flexi-streams:make-in-memory-output-stream)
         :reader probe-sink)
   (closed :initform nil :accessor probe-closed-p))
  (:documentation "A transport that keeps what was written to it and remembers
   whether anyone closed it."))

(defmethod trivial-gray-streams:stream-write-byte
    ((transport handover-probe-transport) byte)
  (write-byte byte (probe-sink transport)))

(defmethod trivial-gray-streams:stream-write-sequence
    ((transport handover-probe-transport) sequence start end &key)
  (write-sequence sequence (probe-sink transport) :start start :end end)
  sequence)

(defmethod close ((transport handover-probe-transport) &key abort)
  (declare (ignore abort))
  (setf (probe-closed-p transport) t))

(defun probe-octets (transport)
  "Everything written to TRANSPORT so far, as one vector."
  (flexi-streams:get-output-stream-sequence (probe-sink transport)))

(test spent-stream-refuses-every-input-and-output-entry-point
  "A stream whose ciphers and transport have gone to a record layer refuses to
   read, to write and to flush, and says which call it refused.

   Each entry point is asked separately and any other error is reported as
   itself rather than as a refusal, so removing the guard shows up as one red
   per entry point instead of as the first one blowing up and hiding the rest."
  (let* ((stream (make-handover-stream (pure-tls::octet-vector 1 2 3 4) 0))
         (layer (pure-tls::adopt-record-layer-from-tls-stream stream)))
    (is (pure-tls::record-layer-p layer)
        "The handover should produce a layer")
    (is (pure-tls::tls-stream-spent-p stream)
        "and should leave the stream spent")
    (loop for (entry . call) in
          (list (cons "reading a byte" (lambda () (read-byte stream)))
                (cons "reading a sequence"
                      (lambda () (read-sequence (pure-tls::make-octet-vector 4)
                                                stream)))
                (cons "writing a byte" (lambda () (write-byte 65 stream)))
                (cons "writing a sequence"
                      (lambda () (write-sequence (pure-tls::octet-vector 65 66)
                                                 stream)))
                (cons "flushing output" (lambda () (force-output stream)))
                (cons "finishing output" (lambda () (finish-output stream))))
          do (multiple-value-bind (outcome report)
                 (handler-case (progn (funcall call) (values :allowed nil))
                   (pure-tls::tls-stream-spent (refusal)
                     (values :refused (princ-to-string refusal)))
                   (error (other)
                     (values :some-other-error (princ-to-string other))))
               (is (eq :refused outcome)
                   "~A on a spent stream should signal TLS-STREAM-SPENT, ~
                    and instead gave ~A~@[: ~A~]"
                   entry outcome report)))
    ;; The refusal is specific enough to act on, rather than something a caller
    ;; has to recognise by reading the message.  Asked so that a stream which
    ;; does not refuse at all fails here too, rather than skipping the check.
    (is (eq :named
            (handler-case (progn (read-byte stream) :not-refused)
              (pure-tls::tls-stream-spent (refusal)
                (if (and (typep refusal 'pure-tls:tls-error)
                         (search "reading a byte" (princ-to-string refusal)))
                    :named
                    :unnamed))))
        "The refusal reports under the library's own condition hierarchy and ~
         names the entry point it refused")))

(test unadopted-stream-serves-every-input-and-output-entry-point
  "The control for the refusals above.  A stream that has not been handed over
   reads, writes and flushes as it always did, so a refusal is a statement about
   this stream rather than about every stream."
  (let* ((payload (pure-tls::octet-vector 1 2 3 4 5 6))
         (stream (make-handover-stream payload 0)))
    (is (not (pure-tls::tls-stream-spent-p stream))
        "A stream that has not been handed over is not spent")
    (is (= 1 (read-byte stream))
        "It reads a byte")
    (let ((taken (pure-tls::make-octet-vector 3)))
      (is (= 3 (read-sequence taken stream))
          "It reads a sequence")
      (is (equalp (pure-tls::octet-vector 2 3 4) taken)
          "and hands back the octets the peer sent, in order"))
    (is (= 65 (write-byte 65 stream))
        "It takes a byte")
    (write-sequence (pure-tls::octet-vector 66 67) stream)
    (is (= 3 (pure-tls::tls-stream-output-position stream))
        "It takes a sequence, and holds what it was given")
    (finish-output stream)
    (is (zerop (pure-tls::tls-stream-output-position stream))
        "and a flush puts the held octets through the record layer")))

(test closing-spent-stream-leaves-the-transport-to-the-layer
  "Closing a spent stream shuts down the stream object and leaves the connection
   alone, because the transport belongs to the layer that took it."
  (let* ((transport (make-instance 'handover-probe-transport))
         (stream (make-handover-stream (pure-tls::octet-vector 7 8 9) 0 transport))
         (layer (pure-tls::adopt-record-layer-from-tls-stream stream)))
    (close stream)
    (is (pure-tls::tls-stream-closed-p stream)
        "The stream object closes")
    (is (not (probe-closed-p transport))
        "without closing the transport it no longer owns")
    (pure-tls::record-layer-write-application-data
     layer (pure-tls::octet-vector 10 11 12))
    (is (plusp (length (probe-octets transport)))
        "and the layer can still put a record on the wire afterwards")))

(test closing-unadopted-stream-closes-the-transport
  "The control for the check above.  A stream that still owns its transport does
   close it, so leaving it open is something a spent stream does and not
   something CLOSE never got round to."
  (let* ((transport (make-instance 'handover-probe-transport))
         (stream (make-handover-stream (pure-tls::octet-vector 7 8 9) 0 transport)))
    (close stream)
    (is (probe-closed-p transport)
        "A stream that owns its transport closes it")))

(test failed-handover-leaves-the-stream-unspent-and-usable
  "A handover either produces a layer or leaves the stream owning everything it
   started with.  There is no state in between, because a stream marked spent
   with nothing having taken the connection is a connection nobody owns."
  ;; Refused before anything moves: the caller tried to supply the plaintext.
  (let* ((payload (pure-tls::octet-vector 20 21 22 23))
         (stream (make-handover-stream payload 0)))
    (signals error
      (pure-tls::adopt-record-layer-from-tls-stream stream :in-plaintext payload))
    (is (not (pure-tls::tls-stream-spent-p stream))
        "A refused handover leaves the stream unspent")
    (is (= 4 (pure-tls::tls-stream-buffer-remaining stream))
        "with its inbound plaintext untouched")
    (is (= 20 (read-byte stream))
        "and a reader picks up where it left off"))
  ;; Refused partway, after the plaintext has been taken off the stream: the
  ;; ciphers the layer requires are not there.
  (let* ((payload (pure-tls::octet-vector 30 31 32 33))
         (stream (make-handover-stream payload 1)))
    (setf (pure-tls::record-layer-read-cipher
           (pure-tls::tls-stream-record-layer stream))
          nil)
    (signals error (pure-tls::adopt-record-layer-from-tls-stream stream))
    (is (not (pure-tls::tls-stream-spent-p stream))
        "A handover that fails partway also leaves the stream unspent")
    (is (= 3 (pure-tls::tls-stream-buffer-remaining stream))
        "with the plaintext put back rather than lost between the two owners")
    (is (= 31 (read-byte stream))
        "and the next octet is the one the reader was owed")
    (write-byte 99 stream)
    (finish-output stream)
    (is (zerop (pure-tls::tls-stream-output-position stream))
        "and the write side still works")))

(defun run-record-tests ()
  "Run all record layer tests."
  (run! 'record-tests))
