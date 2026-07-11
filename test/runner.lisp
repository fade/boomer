;;; test/runner.lisp --- Test runner functions for pure-tls
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>

(in-package #:pure-tls/test)

(defun run-tests ()
  "Run all pure-tls test suites (excluding network-dependent tests).
   Returns T if all tests pass, NIL otherwise."
  (format t "~&=== Running pure-tls Test Suite ===~%~%")
  (let ((results '()))
    (flet ((section (label suite)
             (format t "~%--- ~A ---~%" label)
             (push (run! suite) results)))
      (section "Crypto Tests" 'crypto-tests)
      (section "ML-DSA Tests" 'ml-dsa-tests)
      (section "Record Layer Tests" 'record-tests)
      (section "Handshake Tests" 'handshake-tests)
      (section "Certificate Tests" 'certificate-tests)
      (section "Cancellation Tests" 'cancel-tests)
      (section "Cancellation Integration Tests" 'cancel-integration-tests)
      (section "OpenSSL Tests" 'openssl-tests)
      (section "BoringSSL Pattern Tests" 'boringssl-tests)
      (section "X509test Validation Tests" 'x509test-tests)
      (section "Security Regression Tests" 'security-regression-tests)
      (section "Resumption Interop Tests" 'resumption-interop-tests)
      (section "ACME Client Tests" 'acme-client-tests))
    (format t "~%=== Summary ===~%")
    (format t "Note: Run (run-network-tests) separately for network tests.~%")
    (every #'identity results)))

(defun run-openssl-tests ()
  "Run OpenSSL test suite adaptation tests.
   Returns T if all tests pass, NIL otherwise."
  (format t "~&=== Running OpenSSL Tests ===~%~%")
  (run! 'openssl-tests))

(defun run-ml-dsa-tests ()
  "Run ML-DSA post-quantum signature tests.
   Returns T if all tests pass, NIL otherwise."
  (format t "~&=== Running ML-DSA Tests ===~%~%")
  (run! 'ml-dsa-tests))

(defun run-network-tests ()
  "Run network-dependent tests (requires internet access).
   Returns T if all tests pass, NIL otherwise."
  (format t "~&Running TLS 1.3 network tests...~%~%")
  (run! 'network-tests))
