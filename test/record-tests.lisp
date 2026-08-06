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

(defun make-handover-stream (payload consumed)
  "A blocking TLS stream holding PAYLOAD as decrypted input, of which the
   application has already read the first CONSUMED octets.  The prefix is read
   through the ordinary blocking path so the input position ends up where a real
   application would have left it."
  (let* ((transport (flexi-streams:make-in-memory-output-stream))
         (stream (make-instance 'pure-tls::tls-client-stream :stream transport))
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

(defun record-on-the-wire (content-type body)
  "An input stream carrying one whole unencrypted TLS record."
  (let ((wire (pure-tls::make-octet-vector (+ 5 (length body)))))
    (setf (aref wire 0) content-type
          (aref wire 1) 3
          (aref wire 2) 3
          (aref wire 3) (ldb (byte 8 8) (length body))
          (aref wire 4) (ldb (byte 8 0) (length body)))
    (replace wire body :start1 5)
    (flexi-streams:make-in-memory-input-stream wire)))

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

(defun run-record-tests ()
  "Run all record layer tests."
  (run! 'record-tests))
