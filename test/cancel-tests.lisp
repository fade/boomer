;;; cancel-tests.lisp --- Tests for cancellation (timeout/cancellation via cl-cancel)
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>

(in-package :boomer/test)

(def-suite cancel-tests
    :description "cl-cancel timeout and cancellation tests")

(in-suite cancel-tests)

(test nil-cancel-context-handling
  "Test that NIL cancel context works (backwards compatibility)"
  (finishes
    (boomer::check-tls-context nil)))

(test timeout-basic
  "Test basic timeout functionality with cl-cancel"
  (signals cl-cancel:deadline-exceeded
    (cl-cancel:with-timeout-context (ctx 0.1)
      (sleep 0.2)
      (cl-cancel:check-cancellation ctx))))

(test cancellation-basic
  "Test basic cancellation functionality"
  (multiple-value-bind (ctx cancel-fn)
      (cl-cancel:with-cancel (cl-cancel:background))
    (funcall cancel-fn)
    (signals cl-cancel:cancelled
      (cl-cancel:check-cancellation ctx))))

(test check-cancel-context-tls-error
  "Test that our check-tls-context raises TLS-specific errors"
  (signals boomer:tls-deadline-exceeded
    (cl-cancel:with-timeout-context (ctx 0.1)
      (sleep 0.2)
      (boomer::check-tls-context ctx))))

(test check-cancel-context-cancellation
  "Test that cancellation raises tls-context-cancelled"
  (multiple-value-bind (ctx cancel-fn)
      (cl-cancel:with-cancel (cl-cancel:background))
    (funcall cancel-fn)
    (signals boomer:tls-context-cancelled
      (boomer::check-tls-context ctx))))

(test cancel-context-remaining-time
  "Test context-remaining-time helper for cl-cancel contexts"
  (cl-cancel:with-timeout-context (ctx 10)
    (let ((remaining (boomer::context-remaining-time ctx)))
      (is (and remaining (>= remaining 9) (<= remaining 10))))))

;; Note: Full integration tests (TLS handshake with timeout) require network access
;; and are in network-tests.lisp
