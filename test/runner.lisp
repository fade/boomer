;;; test/runner.lisp --- Test runner functions for boomer
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>

(in-package #:boomer/test)

(defun run-tests ()
  "Run all boomer test suites (excluding network-dependent tests).
   Returns T if all tests pass, NIL otherwise."
  (format t "~&=== Running boomer Test Suite ===~%~%")
  (let ((all-passed t))
    (loop for (label . suite) in '(("Crypto Tests" . crypto-tests)
                                   ("ML-DSA Tests" . ml-dsa-tests)
                                   ("Record Layer Tests" . record-tests)
                                   ("Handshake Tests" . handshake-tests)
                                   ("Certificate Tests" . certificate-tests)
                                   ("Cancellation Tests" . cancel-tests)
                                   ("Cancellation Integration Tests" . cancel-integration-tests)
                                   ("Cancel Monitor Tests" . cancel-monitor-tests)
                                   ("OpenSSL Tests" . openssl-tests)
                                   ("BoringSSL Pattern Tests" . boringssl-tests)
                                   ("X509test Validation Tests" . x509test-tests)
                                   ("Security Regression Tests" . security-regression-tests)
                                   ("Trust Store Tests" . trust-store-tests)
                                   ("Resumption Interop Tests" . resumption-interop-tests))
          do (format t "~&~%--- ~A ---~%" label)
             ;; Every suite runs, whatever the ones before it did, so one failure
             ;; still leaves a full picture of where the build stands.
             (unless (run! suite)
               (setf all-passed nil)))
    (format t "~%=== Summary ===~%")
    (format t "Note: Run (run-network-tests) separately for network tests.~%")
    all-passed))

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
