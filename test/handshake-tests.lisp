;;; test/handshake-tests.lisp --- TLS 1.3 handshake tests
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Tests for TLS 1.3 handshake using RFC 8448 test vectors.
;;; RFC 8448 provides example TLS 1.3 handshakes with complete
;;; cryptographic values for validation.

(in-package #:boomer/test)

(def-suite handshake-tests
  :description "Tests for TLS 1.3 handshake state machine")

(in-suite handshake-tests)

;;;; Note: hex-to-bytes and bytes-equal are defined in crypto-tests.lisp

;;;; RFC 8448 Section 3: Simple 1-RTT Handshake
;;;;
;;;; This section tests key derivation values from the simple handshake example.

;;; Shared secret from ECDHE (X25519)
(defparameter *rfc8448-shared-secret*
  (hex-to-bytes
   "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"))

;;; Early secret (from PSK = 0)
(defparameter *rfc8448-early-secret*
  (hex-to-bytes
   "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"))

;;; Derived secret (for handshake secret derivation)
(defparameter *rfc8448-derived-secret*
  (hex-to-bytes
   "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"))

;;; Handshake secret
(defparameter *rfc8448-handshake-secret*
  (hex-to-bytes
   "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"))

;;; Client handshake traffic secret
(defparameter *rfc8448-client-handshake-traffic-secret*
  (hex-to-bytes
   "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"))

;;; Server handshake traffic secret
(defparameter *rfc8448-server-handshake-traffic-secret*
  (hex-to-bytes
   "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"))

;;; Master secret
(defparameter *rfc8448-master-secret*
  (hex-to-bytes
   "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"))

;;; Client application traffic secret
(defparameter *rfc8448-client-app-traffic-secret*
  (hex-to-bytes
   "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"))

;;; Server application traffic secret
(defparameter *rfc8448-server-app-traffic-secret*
  (hex-to-bytes
   "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"))

;;;; Key Schedule Tests

(test rfc8448-early-secret
  "RFC 8448: Derive early secret from zero PSK"
  (let* ((zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (early-secret (boomer::hkdf-extract zeros zeros :digest :sha256)))
    (is (bytes-equal early-secret *rfc8448-early-secret*)
        "Early secret should match RFC 8448 value")))

(test rfc8448-derived-secret
  "RFC 8448: Derive 'derived' secret for handshake"
  ;; Derive-Secret(Secret, "derived", "") = HKDF-Expand-Label(Secret, "derived", SHA-256(""), 32)
  (let* ((empty-hash (hex-to-bytes
                      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
         (derived (boomer::hkdf-expand-label
                   *rfc8448-early-secret*
                   "derived"
                   empty-hash
                   32
                   :digest :sha256)))
    (is (bytes-equal derived *rfc8448-derived-secret*)
        "Derived secret should match RFC 8448 value")))

(test rfc8448-handshake-secret
  "RFC 8448: Derive handshake secret"
  (let ((handshake-secret (boomer::hkdf-extract
                           *rfc8448-derived-secret*
                           *rfc8448-shared-secret*
                           :digest :sha256)))
    (is (bytes-equal handshake-secret *rfc8448-handshake-secret*)
        "Handshake secret should match RFC 8448 value")))

;;;; ClientHello/ServerHello Transcript Hash
;;;
;;; The transcript hash for these tests is the SHA-256 hash of
;;; ClientHello || ServerHello messages.

(defparameter *rfc8448-hello-transcript-hash*
  (hex-to-bytes
   "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"))

(test rfc8448-client-handshake-traffic-secret
  "RFC 8448: Derive client handshake traffic secret"
  ;; Use hkdf-expand-label directly since we have the pre-computed transcript hash
  ;; derive-secret would hash the input again, causing double-hashing
  (let ((client-hs-secret (boomer::hkdf-expand-label
                           *rfc8448-handshake-secret*
                           "c hs traffic"
                           *rfc8448-hello-transcript-hash*
                           32
                           :digest :sha256)))
    (is (bytes-equal client-hs-secret *rfc8448-client-handshake-traffic-secret*)
        "Client handshake traffic secret should match RFC 8448 value")))

(test rfc8448-server-handshake-traffic-secret
  "RFC 8448: Derive server handshake traffic secret"
  ;; Use hkdf-expand-label directly since we have the pre-computed transcript hash
  (let ((server-hs-secret (boomer::hkdf-expand-label
                           *rfc8448-handshake-secret*
                           "s hs traffic"
                           *rfc8448-hello-transcript-hash*
                           32
                           :digest :sha256)))
    (is (bytes-equal server-hs-secret *rfc8448-server-handshake-traffic-secret*)
        "Server handshake traffic secret should match RFC 8448 value")))

;;;; Key/IV Derivation Tests

(test rfc8448-handshake-key-derivation
  "RFC 8448: Derive handshake traffic keys from traffic secret"
  (let* ((traffic-secret *rfc8448-server-handshake-traffic-secret*)
         (expected-key (hex-to-bytes "3fce516009c21727d0f2e4e86ee403bc"))
         (expected-iv (hex-to-bytes "5d313eb2671276ee13000b30")))
    (let ((key (boomer::hkdf-expand-label traffic-secret "key"
                                             (make-array 0 :element-type '(unsigned-byte 8))
                                             16 :digest :sha256))
          (iv (boomer::hkdf-expand-label traffic-secret "iv"
                                            (make-array 0 :element-type '(unsigned-byte 8))
                                            12 :digest :sha256)))
      (is (bytes-equal key expected-key)
          "Server handshake key should match RFC 8448")
      (is (bytes-equal iv expected-iv)
          "Server handshake IV should match RFC 8448"))))

;;;; Finished Message Tests

(test rfc8448-finished-key-derivation
  "RFC 8448: Derive finished key"
  (let* ((base-key *rfc8448-server-handshake-traffic-secret*)
         (expected-finished-key (hex-to-bytes
                                 "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")))
    (let ((finished-key (boomer::hkdf-expand-label
                         base-key "finished"
                         (make-array 0 :element-type '(unsigned-byte 8))
                         32 :digest :sha256)))
      (is (bytes-equal finished-key expected-finished-key)
          "Server finished key should match RFC 8448"))))

;;;; Extension Parsing Tests

(test parse-supported-versions-extension
  "Test parsing supported_versions extension"
  ;; ClientHello supported_versions: length (1 byte) + versions (2 bytes each)
  ;; 04 = 4 bytes of version data (2 versions × 2 bytes)
  ;; 03 04 = TLS 1.3 (0x0304)
  ;; 03 03 = TLS 1.2 (0x0303)
  (let* ((data (hex-to-bytes "04 0304 0303"))  ; length=4, TLS 1.3, TLS 1.2
         (ext (boomer::parse-supported-versions-extension data)))
    (is (member boomer::+tls-1.3+ (boomer::supported-versions-ext-versions ext))
        "Should contain TLS 1.3")
    (is (member boomer::+tls-1.2+ (boomer::supported-versions-ext-versions ext))
        "Should contain TLS 1.2")))

(test parse-key-share-extension
  "Test parsing key_share extension with X25519"
  ;; Client key_share: length (2) + group (2) + key length (2) + key (32)
  (let* ((key-data (hex-to-bytes "001d0020"))  ; X25519, 32 bytes
         (public-key (boomer:random-bytes 32))
         (full-data (concatenate '(vector (unsigned-byte 8))
                                 (hex-to-bytes "0024")  ; Total length 36
                                 key-data
                                 public-key))
         (ext (boomer::parse-key-share-extension full-data)))
    (is (boomer::key-share-ext-client-shares ext)
        "Should have client shares")
    (let ((share (first (boomer::key-share-ext-client-shares ext))))
      (is (= (boomer::key-share-entry-group share) boomer::+group-x25519+)
          "Group should be X25519"))))

;;;; Cipher Suite Tests

(test cipher-suite-constants
  "Verify cipher suite constants"
  (is (= boomer:+tls-aes-128-gcm-sha256+ #x1301))
  (is (= boomer:+tls-aes-256-gcm-sha384+ #x1302))
  (is (= boomer:+tls-chacha20-poly1305-sha256+ #x1303)))

(test cipher-suite-properties
  "Test cipher suite property functions"
  ;; AES-128-GCM-SHA256
  (is (= (boomer::cipher-suite-key-length boomer:+tls-aes-128-gcm-sha256+) 16))
  (is (= (boomer::cipher-suite-hash-length boomer:+tls-aes-128-gcm-sha256+) 32))
  (is (eql (boomer::cipher-suite-digest boomer:+tls-aes-128-gcm-sha256+) :sha256))

  ;; AES-256-GCM-SHA384
  (is (= (boomer::cipher-suite-key-length boomer:+tls-aes-256-gcm-sha384+) 32))
  (is (= (boomer::cipher-suite-hash-length boomer:+tls-aes-256-gcm-sha384+) 48))
  (is (eql (boomer::cipher-suite-digest boomer:+tls-aes-256-gcm-sha384+) :sha384))

  ;; ChaCha20-Poly1305-SHA256
  (is (= (boomer::cipher-suite-key-length boomer:+tls-chacha20-poly1305-sha256+) 32))
  (is (= (boomer::cipher-suite-hash-length boomer:+tls-chacha20-poly1305-sha256+) 32))
  (is (eql (boomer::cipher-suite-digest boomer:+tls-chacha20-poly1305-sha256+) :sha256)))

;;;; Named Group Tests

(test named-group-constants
  "Verify named group constants"
  (is (= boomer::+group-secp256r1+ #x0017))
  (is (= boomer::+group-x25519+ #x001d)))

;;;; Signature Algorithm Tests

(test signature-algorithm-constants
  "Verify signature algorithm constants"
  (is (= boomer::+sig-rsa-pkcs1-sha256+ #x0401))
  (is (= boomer::+sig-ecdsa-secp256r1-sha256+ #x0403))
  (is (= boomer::+sig-rsa-pss-rsae-sha256+ #x0804))
  (is (= boomer::+sig-ed25519+ #x0807)))

(test ed25519-key-loading
  "Test Ed25519 key loading from PEM files"
  (let ((key-path (merge-pathnames "test/certs/openssl/server-ed25519-key.pem"
                                   (asdf:system-source-directory :boomer)))
        (cert-path (merge-pathnames "test/certs/openssl/server-ed25519-cert.pem"
                                    (asdf:system-source-directory :boomer))))
    ;; Test private key loading
    (let ((key (boomer:load-private-key key-path)))
      (is (typep key 'ironclad::ed25519-private-key)
          "Should load as Ed25519 private key"))
    ;; Test certificate loading
    (let* ((certs (boomer:load-certificate-chain cert-path))
           (cert (first certs))
           (spki (boomer::x509-certificate-subject-public-key-info cert)))
      (is (= (length certs) 1) "Should load one certificate")
      (is (eql (getf spki :algorithm) :ed25519)
          "Certificate should have Ed25519 public key"))))

(test ed25519-signing-verification
  "Test Ed25519 signing and verification"
  (let* ((key-path (merge-pathnames "test/certs/openssl/server-ed25519-key.pem"
                                    (asdf:system-source-directory :boomer)))
         (key (boomer:load-private-key key-path))
         (data (make-array 64 :element-type '(unsigned-byte 8) :initial-element 42)))
    ;; Test that Ed25519 is recognized as valid algorithm for this key
    (let ((algos (boomer::signature-algorithms-for-private-key key)))
      (is (member boomer::+sig-ed25519+ algos)
          "Ed25519 should be in valid algorithms for key"))
    ;; Test signing
    (let ((sig (boomer::sign-data-with-algorithm data key boomer::+sig-ed25519+)))
      (is (= (length sig) 64) "Ed25519 signature should be 64 bytes")
      ;; Test verification
      (let ((pub-key-bytes (ironclad:ed25519-key-y key)))
        (is (= (length pub-key-bytes) 32) "Ed25519 public key should be 32 bytes")
        ;; Verification should not throw
        (finishes (boomer::verify-ed25519-signature pub-key-bytes data sig))))))

(test ed25519-in-supported-algorithms
  "Test Ed25519 is included in supported signature algorithms"
  (let ((algos (boomer::supported-signature-algorithms-tls13)))
    (is (member boomer::+sig-ed25519+ algos)
        "Ed25519 should be in TLS 1.3 supported signature algorithms")))

(test ed25519-server-handshake
  "Test Ed25519 server-side TLS handshake"
  (let* ((cert-path (merge-pathnames "test/certs/openssl/server-ed25519-cert.pem"
                                     (asdf:system-source-directory :boomer)))
         (key-path (merge-pathnames "test/certs/openssl/server-ed25519-key.pem"
                                    (asdf:system-source-directory :boomer)))
         (port (+ 20000 (random 1000)))
         (server-result (list nil))
         (ready-lock (bt:make-lock "server-ready"))
         (ready-cv (bt:make-condition-variable :name "server-ready-cv"))
         (ready-flag (list nil)))
    ;; Start server in background
    (bt:make-thread
     (lambda ()
       (let ((server-socket nil)
             (client-socket nil))
         (unwind-protect
             (handler-case
                 (progn
                   (setf server-socket
                         (usocket:socket-listen "127.0.0.1" port
                                                :reuse-address t
                                                :element-type '(unsigned-byte 8)))
                   ;; Signal ready
                   (bt:with-lock-held (ready-lock)
                     (setf (first ready-flag) t)
                     (bt:condition-notify ready-cv))
                   ;; Accept connection
                   (setf client-socket
                         (usocket:socket-accept server-socket
                                                :element-type '(unsigned-byte 8)))
                   ;; Create TLS server stream with Ed25519 certificate
                   (let ((tls-stream
                           (boomer:make-tls-server-stream
                            (usocket:socket-stream client-socket)
                            :certificate cert-path
                            :key key-path)))
                     (close tls-stream)
                     (setf (first server-result) :success)))
               (error (e)
                 (setf (first server-result) (format nil "~A" e))))
           (when client-socket (ignore-errors (usocket:socket-close client-socket)))
           (when server-socket (ignore-errors (usocket:socket-close server-socket))))))
     :name "ed25519-test-server")
    ;; Wait for server ready
    (bt:with-lock-held (ready-lock)
      (loop until (first ready-flag)
            do (bt:condition-wait ready-cv ready-lock :timeout 5)))
    (sleep 0.05)
    ;; Connect client
    (let ((client-socket nil))
      (unwind-protect
          (handler-case
              (progn
                (setf client-socket
                      (usocket:socket-connect "127.0.0.1" port
                                              :element-type '(unsigned-byte 8)))
                (let ((tls-stream
                        (boomer:make-tls-client-stream
                         (usocket:socket-stream client-socket)
                         :sni-hostname "ed25519-test"
                         :verify boomer:+verify-none+)))
                  (close tls-stream)
                  (sleep 0.1)  ; Let server finish
                  (is (eql (first server-result) :success)
                      "Server handshake should succeed with Ed25519 certificate")))
            (error (e)
              (fail "Client connection failed: ~A" e)))
        (when client-socket (ignore-errors (usocket:socket-close client-socket)))))))

;;;; Ed448 Tests

(test ed448-key-loading
  "Test Ed448 key loading from PEM files"
  (let ((key-path (merge-pathnames "test/certs/openssl/server-ed448-key.pem"
                                   (asdf:system-source-directory :boomer)))
        (cert-path (merge-pathnames "test/certs/openssl/server-ed448-cert.pem"
                                    (asdf:system-source-directory :boomer))))
    ;; Test private key loading
    (let ((key (boomer:load-private-key key-path)))
      (is (typep key 'ironclad::ed448-private-key)
          "Should load as Ed448 private key"))
    ;; Test certificate loading
    (let* ((certs (boomer:load-certificate-chain cert-path))
           (cert (first certs))
           (spki (boomer::x509-certificate-subject-public-key-info cert)))
      (is (= (length certs) 1) "Should load one certificate")
      (is (eql (getf spki :algorithm) :ed448)
          "Certificate should have Ed448 public key"))))

(test ed448-signing-verification
  "Test Ed448 signing and verification"
  (let* ((key-path (merge-pathnames "test/certs/openssl/server-ed448-key.pem"
                                    (asdf:system-source-directory :boomer)))
         (key (boomer:load-private-key key-path))
         (data (make-array 64 :element-type '(unsigned-byte 8) :initial-element 42)))
    ;; Test that Ed448 is recognized as valid algorithm for this key
    (let ((algos (boomer::signature-algorithms-for-private-key key)))
      (is (member boomer::+sig-ed448+ algos)
          "Ed448 should be in valid algorithms for key"))
    ;; Test signing
    (let ((sig (boomer::sign-data-with-algorithm data key boomer::+sig-ed448+)))
      (is (= (length sig) 114) "Ed448 signature should be 114 bytes")
      ;; Test verification
      (let ((pub-key-bytes (ironclad:ed448-key-y key)))
        (is (= (length pub-key-bytes) 57) "Ed448 public key should be 57 bytes")
        ;; Verification should not throw
        (finishes (boomer::verify-ed448-signature pub-key-bytes data sig))))))

(test ed448-in-supported-algorithms
  "Test Ed448 is included in supported signature algorithms"
  (let ((algos (boomer::supported-signature-algorithms-tls13)))
    (is (member boomer::+sig-ed448+ algos)
        "Ed448 should be in TLS 1.3 supported signature algorithms")))

(test ed448-server-handshake
  "Test Ed448 server-side TLS handshake"
  (let* ((cert-path (merge-pathnames "test/certs/openssl/server-ed448-cert.pem"
                                     (asdf:system-source-directory :boomer)))
         (key-path (merge-pathnames "test/certs/openssl/server-ed448-key.pem"
                                    (asdf:system-source-directory :boomer)))
         (port (+ 20000 (random 1000)))
         (server-result (list nil))
         (ready-lock (bt:make-lock "server-ready"))
         (ready-cv (bt:make-condition-variable :name "server-ready-cv"))
         (ready-flag (list nil)))
    ;; Start server in background
    (bt:make-thread
     (lambda ()
       (let ((server-socket nil)
             (client-socket nil))
         (unwind-protect
             (handler-case
                 (progn
                   (setf server-socket
                         (usocket:socket-listen "127.0.0.1" port
                                                :reuse-address t
                                                :element-type '(unsigned-byte 8)))
                   ;; Signal ready
                   (bt:with-lock-held (ready-lock)
                     (setf (first ready-flag) t)
                     (bt:condition-notify ready-cv))
                   ;; Accept connection
                   (setf client-socket
                         (usocket:socket-accept server-socket
                                                :element-type '(unsigned-byte 8)))
                   ;; Create TLS server stream with Ed448 certificate
                   (let ((tls-stream
                           (boomer:make-tls-server-stream
                            (usocket:socket-stream client-socket)
                            :certificate cert-path
                            :key key-path)))
                     (close tls-stream)
                     (setf (first server-result) :success)))
               (error (e)
                 (setf (first server-result) (format nil "~A" e))))
           (when client-socket (ignore-errors (usocket:socket-close client-socket)))
           (when server-socket (ignore-errors (usocket:socket-close server-socket))))))
     :name "ed448-test-server")
    ;; Wait for server ready
    (bt:with-lock-held (ready-lock)
      (loop until (first ready-flag)
            do (bt:condition-wait ready-cv ready-lock :timeout 5)))
    (sleep 0.05)
    ;; Connect client
    (let ((client-socket nil))
      (unwind-protect
          (handler-case
              (progn
                (setf client-socket
                      (usocket:socket-connect "127.0.0.1" port
                                              :element-type '(unsigned-byte 8)))
                (let ((tls-stream
                        (boomer:make-tls-client-stream
                         (usocket:socket-stream client-socket)
                         :sni-hostname "ed448-test"
                         :verify boomer:+verify-none+)))
                  (close tls-stream)
                  (sleep 0.1)  ; Let server finish
                  (is (eql (first server-result) :success)
                      "Server handshake should succeed with Ed448 certificate")))
            (error (e)
              (fail "Client connection failed: ~A" e)))
        (when client-socket (ignore-errors (usocket:socket-close client-socket)))))))

;;;; Key Exchange Tests

(test x25519-key-exchange
  "Test X25519 key exchange generates valid keys"
  (let ((kex (boomer::generate-key-exchange boomer::+group-x25519+)))
    (is (= (boomer::key-exchange-group kex) boomer::+group-x25519+)
        "Group should be X25519")
    (is (= (length (boomer::key-exchange-public-key kex)) 32)
        "X25519 public key should be 32 bytes")))

(test x25519-shared-secret
  "Test X25519 shared secret computation"
  (let* ((alice (boomer::generate-key-exchange boomer::+group-x25519+))
         (bob (boomer::generate-key-exchange boomer::+group-x25519+))
         (alice-shared (boomer::compute-shared-secret
                        alice (boomer::key-exchange-public-key bob)))
         (bob-shared (boomer::compute-shared-secret
                      bob (boomer::key-exchange-public-key alice))))
    (is (bytes-equal alice-shared bob-shared)
        "Both parties should compute same shared secret")
    (is (= (length alice-shared) 32)
        "Shared secret should be 32 bytes")))

(test secp256r1-key-exchange
  "Test secp256r1 key exchange generates valid keys"
  (let ((kex (boomer::generate-key-exchange boomer::+group-secp256r1+)))
    (is (= (boomer::key-exchange-group kex) boomer::+group-secp256r1+)
        "Group should be secp256r1")
    (is (= (length (boomer::key-exchange-public-key kex)) 65)
        "secp256r1 uncompressed public key should be 65 bytes")))

;;;; HelloRetryRequest Tests

(test hello-retry-request-magic-random
  "Test that HRR is detected by magic random value"
  (let* ((hrr-random boomer::+hello-retry-request-random+)
         (normal-random (boomer::random-bytes 32))
         ;; Create a mock ServerHello with HRR random
         (hrr-hello (boomer::make-server-hello
                     :legacy-version boomer::+tls-1.2+
                     :random hrr-random
                     :legacy-session-id-echo (make-array 0 :element-type '(unsigned-byte 8))
                     :cipher-suite boomer::+tls-aes-128-gcm-sha256+
                     :legacy-compression-method 0
                     :extensions nil))
         ;; Create a normal ServerHello
         (normal-hello (boomer::make-server-hello
                        :legacy-version boomer::+tls-1.2+
                        :random normal-random
                        :legacy-session-id-echo (make-array 0 :element-type '(unsigned-byte 8))
                        :cipher-suite boomer::+tls-aes-128-gcm-sha256+
                        :legacy-compression-method 0
                        :extensions nil)))
    (is (boomer::hello-retry-request-p hrr-hello)
        "ServerHello with magic random should be detected as HRR")
    (is (not (boomer::hello-retry-request-p normal-hello))
        "Normal ServerHello should not be detected as HRR")))

(test hello-retry-request-key-share-serialization
  "Test that HRR key_share extension serializes correctly (just selected_group)"
  (let* ((ext (boomer::make-key-share-ext :selected-group boomer::+group-x25519+))
         (serialized (boomer::serialize-key-share-extension ext)))
    ;; HRR key_share should be just 2 bytes (the group)
    (is (= (length serialized) 2)
        "HRR key_share should be 2 bytes (just the group)")
    (is (= (boomer::decode-uint16 serialized 0) boomer::+group-x25519+)
        "Serialized group should match")))

;;;; ECH (Encrypted Client Hello) Tests

(test hpke-round-trip
  "Test HPKE encryption/decryption round-trip"
  ;; Generate receiver key pair using Ironclad's X25519
  ;; generate-key-pair returns (values private-key public-key)
  (multiple-value-bind (sk-r pk-r-key)
      (ironclad:generate-key-pair :curve25519)
    (let* ((pk-r (ironclad:curve25519-key-y pk-r-key))
           (info (boomer::make-octet-vector 0))
           (aad (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAB))
           (plaintext (make-array 100 :element-type '(unsigned-byte 8) :initial-element 42)))
      ;; Test single-shot API
      (multiple-value-bind (enc ciphertext)
          (boomer::hpke-seal pk-r info aad plaintext
                                :kem-id boomer::+hpke-kem-x25519-sha256+
                                :kdf-id boomer::+hpke-kdf-hkdf-sha256+
                                :aead-id boomer::+hpke-aead-aes-128-gcm+)
        (is (= (length enc) 32) "X25519 encapsulated key should be 32 bytes")
        (is (> (length ciphertext) (length plaintext)) "Ciphertext should be longer (AEAD tag)")
        ;; Decrypt - note: hpke-open arg order is (enc sk-r info aad ct ...)
        (let ((decrypted (boomer::hpke-open enc sk-r info aad ciphertext
                                              :kem-id boomer::+hpke-kem-x25519-sha256+
                                              :kdf-id boomer::+hpke-kdf-hkdf-sha256+
                                              :aead-id boomer::+hpke-aead-aes-128-gcm+)))
          (is (bytes-equal decrypted plaintext) "Decrypted should match plaintext"))))))

(test ech-config-serialization
  "Test ECH config serialization/parsing round-trip"
  (let* ((key-config (boomer::make-ech-hpke-key-config
                      :config-id 42
                      :kem-id boomer::+hpke-kem-x25519-sha256+
                      :public-key (boomer:random-bytes 32)
                      :cipher-suites (list (boomer::make-ech-hpke-cipher-suite
                                            :kdf-id boomer::+hpke-kdf-hkdf-sha256+
                                            :aead-id boomer::+hpke-aead-aes-128-gcm+))))
         (contents (boomer::make-ech-config-contents
                    :key-config key-config
                    :maximum-name-length 128
                    :public-name "test.example.com"
                    :extensions (boomer::make-octet-vector 0)))
         (config (boomer::make-ech-config
                  :version boomer::+ech-version+
                  :contents contents))
         (serialized (boomer::serialize-ech-config-list (list config)))
         (parsed (boomer::parse-ech-config-list serialized)))
    (is (= (length parsed) 1) "Should parse one config")
    (let* ((parsed-config (first parsed))
           (parsed-contents (boomer::ech-config-contents parsed-config))
           (parsed-key-config (boomer::ech-config-contents-key-config parsed-contents)))
      (is (= (boomer::ech-config-version parsed-config) boomer::+ech-version+)
          "Version should match")
      (is (= (boomer::ech-hpke-key-config-config-id parsed-key-config) 42)
          "Config ID should match")
      (is (string= (boomer::ech-config-contents-public-name parsed-contents) "test.example.com")
          "Public name should match"))))

(test ech-extension-serialization
  "Test ECH extension serialization/parsing"
  ;; Test outer extension
  (let* ((outer-ext (boomer::make-ech-ext
                     :type :outer
                     :config-id 99
                     :cipher-suite (boomer::make-ech-hpke-cipher-suite
                                    :kdf-id boomer::+hpke-kdf-hkdf-sha256+
                                    :aead-id boomer::+hpke-aead-aes-128-gcm+)
                     :enc (boomer:random-bytes 32)
                     :payload (boomer:random-bytes 100)))
         (serialized (boomer::serialize-ech-extension outer-ext))
         (parsed (boomer::parse-ech-extension serialized)))
    (is (eql (boomer::ech-ext-type parsed) :outer) "Type should be :outer")
    (is (= (boomer::ech-ext-config-id parsed) 99) "Config ID should match"))
  ;; Test inner extension
  (let* ((inner-ext (boomer::make-ech-ext :type :inner))
         (serialized (boomer::serialize-ech-extension inner-ext))
         (parsed (boomer::parse-ech-extension serialized)))
    (is (eql (boomer::ech-ext-type parsed) :inner) "Type should be :inner")
    (is (= (length serialized) 1) "Inner extension should be 1 byte")))

(test ech-config-selection
  "Test ECH config selection picks compatible config"
  (let* ((key-config (boomer::make-ech-hpke-key-config
                      :config-id 1
                      :kem-id boomer::+hpke-kem-x25519-sha256+
                      :public-key (boomer:random-bytes 32)
                      :cipher-suites (list (boomer::make-ech-hpke-cipher-suite
                                            :kdf-id boomer::+hpke-kdf-hkdf-sha256+
                                            :aead-id boomer::+hpke-aead-aes-128-gcm+))))
         (contents (boomer::make-ech-config-contents
                    :key-config key-config
                    :maximum-name-length 128
                    :public-name "example.com"
                    :extensions (boomer::make-octet-vector 0)))
         (config (boomer::make-ech-config
                  :version boomer::+ech-version+
                  :contents contents)))
    (multiple-value-bind (selected cipher-suite)
        (boomer::select-ech-config (list config))
      (is (not (null selected)) "Should select a config")
      (is (not (null cipher-suite)) "Should select a cipher suite")
      (is (= (boomer::ech-hpke-cipher-suite-kdf-id cipher-suite)
             boomer::+hpke-kdf-hkdf-sha256+)
          "Should select SHA256 KDF"))))

(test ech-inner-clienthello-encoding
  "Test inner ClientHello encoding and padding"
  (let* ((inner-hello (boomer::make-client-hello
                       :legacy-version boomer::+tls-1.2+
                       :random (boomer:random-bytes 32)
                       :legacy-session-id (boomer::make-octet-vector 0)
                       :cipher-suites (list boomer::+tls-aes-128-gcm-sha256+)
                       :legacy-compression-methods (boomer::octet-vector 0)
                       :extensions (list
                                    (boomer::make-tls-extension
                                     :type boomer::+extension-server-name+
                                     :data (boomer::make-server-name-ext
                                            :host-name "secret.example.com"))
                                    (boomer::make-tls-extension
                                     :type boomer::+extension-supported-versions+
                                     :data (boomer::make-supported-versions-ext
                                            :versions (list boomer::+tls-1.3+))))))
         ;; Add ECH inner marker
         (with-marker (boomer::add-ech-inner-marker inner-hello)))
    ;; Check inner has ECH extension
    (let ((ech-ext (boomer::find-extension
                    (boomer::client-hello-extensions with-marker)
                    boomer::+extension-ech+)))
      (is (not (null ech-ext)) "Inner CH should have ECH extension")
      (is (eql (boomer::ech-ext-type (boomer::tls-extension-data ech-ext)) :inner)
          "ECH extension should be inner type"))
    ;; Test encoding with padding
    (let ((encoded (boomer::encode-client-hello-inner with-marker 128)))
      (is (> (length encoded) 0) "Encoded inner should have content"))))

(test ech-outer-clienthello-construction
  "Test outer ClientHello construction with ECH"
  (let* ((key-config (boomer::make-ech-hpke-key-config
                      :config-id 77
                      :kem-id boomer::+hpke-kem-x25519-sha256+
                      :public-key (boomer:random-bytes 32)
                      :cipher-suites (list (boomer::make-ech-hpke-cipher-suite
                                            :kdf-id boomer::+hpke-kdf-hkdf-sha256+
                                            :aead-id boomer::+hpke-aead-aes-128-gcm+))))
         (contents (boomer::make-ech-config-contents
                    :key-config key-config
                    :maximum-name-length 128
                    :public-name "cloudflare-ech.com"
                    :extensions (boomer::make-octet-vector 0)))
         (config (boomer::make-ech-config
                  :version boomer::+ech-version+
                  :contents contents))
         (cipher-suite (first (boomer::ech-hpke-key-config-cipher-suites key-config)))
         (inner-hello (boomer::make-client-hello
                       :legacy-version boomer::+tls-1.2+
                       :random (boomer:random-bytes 32)
                       :legacy-session-id (boomer:random-bytes 32)
                       :cipher-suites (list boomer::+tls-aes-128-gcm-sha256+)
                       :legacy-compression-methods (boomer::octet-vector 0)
                       :extensions (list
                                    (boomer::make-tls-extension
                                     :type boomer::+extension-server-name+
                                     :data (boomer::make-server-name-ext
                                            :host-name "secret-server.example.com"))))))
    ;; Build outer extensions
    (let* ((inner-with-marker (boomer::add-ech-inner-marker inner-hello))
           (encoded (boomer::encode-client-hello-inner inner-with-marker 128)))
      (multiple-value-bind (enc ciphertext)
          (boomer::encrypt-client-hello-inner encoded config cipher-suite)
        (let ((outer-exts (boomer::build-outer-extensions
                           (boomer::client-hello-extensions inner-hello)
                           "cloudflare-ech.com"
                           config cipher-suite enc ciphertext)))
          ;; Check SNI is public_name
          (let ((sni-ext (boomer::find-extension outer-exts boomer::+extension-server-name+)))
            (is (not (null sni-ext)) "Outer should have SNI extension")
            (is (string= (boomer::server-name-ext-host-name
                          (boomer::tls-extension-data sni-ext))
                         "cloudflare-ech.com")
                "Outer SNI should be public_name"))
          ;; Check ECH extension is present
          (let ((ech-ext (boomer::find-extension outer-exts boomer::+extension-ech+)))
            (is (not (null ech-ext)) "Outer should have ECH extension")
            (is (eql (boomer::ech-ext-type (boomer::tls-extension-data ech-ext)) :outer)
                "Outer ECH should be :outer type")))))))

(test ech-constants
  "Verify ECH and HPKE constants are defined"
  (is (= boomer::+extension-ech+ #xfe0d))
  (is (= boomer::+ech-version+ #xfe0d))
  (is (zerop boomer::+hpke-mode-base+))
  (is (= boomer::+hpke-kem-x25519-sha256+ #x0020))
  (is (= boomer::+hpke-kdf-hkdf-sha256+ #x0001))
  (is (= boomer::+hpke-aead-aes-128-gcm+ #x0001)))

;;;; Test Runner

;;;; ---------------------------------------------------------------------------
;;;; ServerHello hardening: compression-off + TLS-1.3 version floor.
;;;;
;;;; process-server-hello fails closed on three malformed/hostile ServerHellos,
;;;; each signalling boomer:tls-handshake-error after writing a fatal alert to
;;;; the record layer:
;;;;   (1) legacy_compression_method != 0 (RFC 8446 4.1.3) -> decode_error.
;;;;   (2) a TLS 1.3 downgrade sentinel (DOWNGRD01 / DOWNGRD00) in the last 8
;;;;       bytes of ServerHello.random (RFC 8446 4.1.3) -> illegal_parameter.
;;;;   (3) supported_versions.selected_version != TLS 1.3 -> reject (we are a
;;;;       TLS-1.3-only client; anything lower is refused).
;;;;
;;;; The driver stands up a minimal in-memory client-handshake + record-layer
;;;; (an in-memory output stream, no socket) so the fatal-alert write succeeds
;;;; and the rejection can be observed as a raised condition.  Each test starts
;;;; from an otherwise-valid ServerHello and flips exactly one field, so the
;;;; rejection is attributable to the field under test (verified: the messages
;;;; are the compression, downgrade-sentinel, and version-floor errors
;;;; respectively; no earlier check pre-empts them).
;;;; ---------------------------------------------------------------------------

(defun %drive-server-hello (server-hello)
  "Drive process-server-hello against SERVER-HELLO using a minimal in-memory
   client-handshake + record-layer (no socket).  Fatal alerts are written into
   an in-memory stream, so the ServerHello rejections fire without a live
   connection.  Signals whatever process-server-hello signals."
  (let* ((out (flexi-streams:make-in-memory-output-stream))
         (rl (boomer::make-record-layer out))
         (hs (boomer::make-client-handshake
              :record-layer rl
              :legacy-session-id (boomer::make-octet-vector 0)
              :cipher-suites (list boomer::+tls-aes-128-gcm-sha256+)))
         (msg (boomer::make-handshake-message :type 2 :body server-hello))
         (raw (boomer::make-octet-vector 40)))
    (boomer::process-server-hello hs msg raw)))

(defun %sentinel-free-random ()
  "A 32-byte ServerHello.random with bytes 24..31 forced to a fixed non-sentinel
   pattern, so the downgrade-sentinel check is not tripped incidentally."
  (let ((r (boomer::random-bytes 32)))
    (loop for i from 24 below 32 do (setf (aref r i) #x11))
    r))

(defun %supported-versions-server-hello-ext (version)
  "A supported_versions ServerHello extension selecting VERSION."
  (boomer::make-tls-extension
   :type boomer::+extension-supported-versions+
   :data (boomer::make-supported-versions-ext :selected-version version)))

(test server-hello-nonzero-compression-rejected
  "RFC 8446 4.1.3: a ServerHello with legacy_compression_method != 0 must be
   rejected with a fatal handshake error."
  (signals boomer:tls-handshake-error
    (%drive-server-hello
     (boomer::make-server-hello
      :random (%sentinel-free-random)
      :legacy-session-id-echo (boomer::make-octet-vector 0)
      :cipher-suite boomer::+tls-aes-128-gcm-sha256+
      :legacy-compression-method 1
      :extensions (list (%supported-versions-server-hello-ext boomer::+tls-1.3+))))))

(test server-hello-downgrade-sentinel-rejected
  "RFC 8446 4.1.3: a TLS 1.3 downgrade sentinel in the last 8 bytes of
   ServerHello.random must be rejected with a fatal handshake error."
  ;; DOWNGRD01 (server negotiated <= TLS 1.2 while capable of 1.3).
  (signals boomer:tls-handshake-error
    (%drive-server-hello
     (let ((r (%sentinel-free-random)))
       (replace r (boomer::hex-to-octets "444F574E47524401") :start1 24)
       (boomer::make-server-hello
        :random r
        :legacy-session-id-echo (boomer::make-octet-vector 0)
        :cipher-suite boomer::+tls-aes-128-gcm-sha256+
        :legacy-compression-method 0
        :extensions (list (%supported-versions-server-hello-ext boomer::+tls-1.3+))))))
  ;; DOWNGRD00 (server negotiated <= TLS 1.1) must be rejected too.
  (signals boomer:tls-handshake-error
    (%drive-server-hello
     (let ((r (%sentinel-free-random)))
       (replace r (boomer::hex-to-octets "444F574E47524400") :start1 24)
       (boomer::make-server-hello
        :random r
        :legacy-session-id-echo (boomer::make-octet-vector 0)
        :cipher-suite boomer::+tls-aes-128-gcm-sha256+
        :legacy-compression-method 0
        :extensions (list (%supported-versions-server-hello-ext boomer::+tls-1.3+)))))))

(test server-hello-below-tls-1.3-rejected
  "TLS-1.3-only client: a ServerHello whose supported_versions selects a version
   below TLS 1.3 must be rejected with a fatal handshake error."
  (signals boomer:tls-handshake-error
    (%drive-server-hello
     (boomer::make-server-hello
      :random (%sentinel-free-random)
      :legacy-session-id-echo (boomer::make-octet-vector 0)
      :cipher-suite boomer::+tls-aes-128-gcm-sha256+
      :legacy-compression-method 0
      :extensions (list (%supported-versions-server-hello-ext boomer::+tls-1.2+))))))

(defun run-handshake-tests ()
  "Run all handshake tests."
  (run! 'handshake-tests))
