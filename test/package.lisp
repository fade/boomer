;;; test/package.lisp --- Test package for boomer
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>

(in-package #:cl-user)

(defpackage #:boomer/test
  (:use #:cl #:fiveam)
  (:export
   #:run-tests
   #:run-crypto-tests
   #:run-record-tests
   #:run-handshake-tests
   #:run-certificate-tests
   #:run-network-tests
   #:run-openssl-tests
   #:run-boringssl-tests
   #:run-x509test-tests
   #:run-security-regression-tests
   ;; Test suites
   #:crypto-tests
   #:record-tests
   #:handshake-tests
   #:certificate-tests
   #:network-tests
   #:openssl-tests
   #:boringssl-tests
   #:x509test-tests
   #:security-regression-tests
   #:resumption-interop-tests))
