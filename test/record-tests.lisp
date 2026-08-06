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

(defun run-record-tests ()
  "Run all record layer tests."
  (run! 'record-tests))
