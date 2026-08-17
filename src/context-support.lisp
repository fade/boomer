;;; context-support.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Request context support for timeouts and cancellation using cl-cancel.

(in-package :boomer)

;;; Conditions

(define-condition tls-context-cancelled (tls-error)
  ((context :initarg :context :reader context-cancelled-context))
  (:report (lambda (condition stream)
             (declare (ignore condition))
             (format stream "TLS operation cancelled via request context")))
  (:documentation "Signaled when a TLS operation is cancelled via its request context."))

(define-condition tls-deadline-exceeded (tls-error)
  ((context :initarg :context :reader deadline-exceeded-context)
   (deadline :initarg :deadline :reader deadline-exceeded-deadline))
  (:report (lambda (condition stream)
             (declare (ignore condition))
             (format stream "TLS operation exceeded deadline")))
  (:documentation "Signaled when a TLS operation exceeds its deadline."))

;;; Helper functions

(defun check-tls-context (&optional (ctx cl-cancel:*current-cancel-context*))
  "Check if context CTX is cancelled or past its deadline.
   Signals appropriate TLS error if so. Returns NIL if context is still valid or is NIL.
   Uses *current-cancel-context* by default for automatic propagation."
  (when ctx
    (handler-case
        (cl-cancel:check-cancellation ctx)
      (cl-cancel:deadline-exceeded ()
        (error 'tls-deadline-exceeded
               :context ctx
               :deadline (cl-cancel:deadline ctx)))
      (cl-cancel:cancelled ()
        (error 'tls-context-cancelled
               :context ctx))))
  nil)

(defun context-remaining-time (ctx)
  "Return the remaining time in seconds for context CTX, or NIL if no deadline.
   Returns 0 if deadline is already exceeded."
  (when ctx
    (let ((deadline (cl-cancel:deadline ctx)))
      (when deadline
        (max 0 (- deadline (cl-cancel:get-current-time)))))))

(defun effective-timeout (&optional (default 10))
  "Return effective timeout in seconds based on current context.
   Uses context remaining time if available, otherwise DEFAULT.
   Caps at 30 seconds to avoid excessive waits."
  (let* ((ctx cl-cancel:*current-cancel-context*)
         (remaining (when ctx (context-remaining-time ctx))))
    (cond
      ((and remaining (plusp remaining)) (min remaining 30))
      (remaining 0)  ; Deadline already exceeded
      (t default))))

(defmacro with-optional-timeout ((var timeout-seconds) &body body)
  "Execute BODY with an optional timeout context bound to VAR.
   If TIMEOUT-SECONDS is NIL, VAR is bound to NIL (no timeout).
   Otherwise, creates a context with the specified deadline."
  (let ((timeout-sym (gensym "TIMEOUT-")))
    `(let ((,timeout-sym ,timeout-seconds))
       (if ,timeout-sym
           (cl-cancel:with-timeout-context (,var ,timeout-sym)
             ,@body)
           (let ((,var nil))
             ,@body)))))

;;; Close-on-cancel monitoring for immediate cancellation

(defun setup-close-on-cancel (context socket)
  "Set up automatic closure of SOCKET when CONTEXT is cancelled or deadline exceeded.
   Returns a release function that must be called once SOCKET is no longer this
   caller's to close.  This enables immediate interruption of blocking I/O
   operations, which cooperative checking between reads cannot provide.

   The release function may be called any number of times; only the first call
   does anything, and it never signals.  Both matter to the callers, which run it
   from close and handover paths where an error would turn tidying up into a
   failure of the operation that asked for it."
  (if context
      (let ((release (cl-cancel:close-stream-on-cancel socket context))
            (released nil))
        (lambda ()
          (unless released
            (setf released t)
            ;; Releasing is two acts: telling the monitor to leave SOCKET alone,
            ;; and waiting for its thread to finish.  Only the second can fail,
            ;; and it does fail against bordeaux-threads releases whose
            ;; JOIN-THREAD accepts no timeout argument.  The first act has
            ;; already taken effect by then, so the failure is not worth
            ;; propagating to a caller that is closing a stream.
            (handler-case (funcall release)
              (error () nil)))
          nil))
      (lambda () nil)))

;;; Hostname-verification policy

(defstruct hostname-policy
  "Orthogonal RFC 6125 hostname-verification knobs threaded into VERIFY-HOSTNAME.

   ALLOW-WILDCARDS   - When true (default), wildcard-pattern SANs (\"*.\" left
     label) are matched per RFC 6125 via the general matcher.  When NIL, such
     SANs are excluded from matching.
   ALLOW-CN-FALLBACK - When true (default), a certificate carrying no
     subjectAltName may be matched against its Subject Common Name (deprecated
     but still widely deployed).  When NIL, identity is trusted only through the
     subjectAltName and a no-SAN certificate is rejected outright."
  (allow-wildcards   t)
  (allow-cn-fallback t))

(defvar *general-hostname-policy* (make-hostname-policy)
  "The default hostname-verification policy: the general RFC 6125 profile.
   Honors wildcard SANs via the general matcher and permits Common Name
   fallback when no subjectAltName is present.  Preserves the library's
   general-purpose behaviour for every caller that does not compose a stricter
   policy.")

(defvar *strict-privacy-hostname-policy*
  (make-hostname-policy :allow-wildcards nil :allow-cn-fallback nil)
  "An opt-in composition for RFC 8310 section 8.1 Strict Privacy: an identity is
   trusted only through the certificate's subjectAltName (Common Name is never
   consulted, a no-SAN certificate is rejected) and wildcard SANs are excluded.
   Selected by a consumer -- e.g. a DNS-over-TLS resolver authenticating a
   specific resolver name -- via the context constructor; it is never the
   library default.")
