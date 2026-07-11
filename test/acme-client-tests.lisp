;;; test/acme-client-tests.lisp --- ACME client regression tests
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Regression tests for RFC 8555 nonce handling in the ACME client.  Both tests
;;; rebind acme::*http-request-function* to a stub closure so the client runs
;;; without a live CA, matching drakma:http-request's (body status headers)
;;; multiple-value signature.
;;;
;;;   * badNonce retry (RFC 8555 Section 6.5) -- a badNonce response must be
;;;     retried exactly once, re-signed with the fresh Replay-Nonce.
;;;   * poll-status non-string state -- a problem document's NUMERIC :status must
;;;     not crash the polling loop.

(in-package #:pure-tls/test)

(def-suite acme-client-tests
  :description "ACME client nonce-handling regression tests (RFC 8555 6.5).")

(in-suite acme-client-tests)

(defun %make-stub-acme-client ()
  "Build a minimal acme-client with a real EC P-256 account key and a directory
   providing a new-nonce endpoint, without touching the on-disk store."
  (acme::%make-acme-client
   :account-key (ironclad:generate-key-pair :secp256r1)
   :directory '((:new-nonce . "https://acme.test/new-nonce"))))

(defun %protected-nonce (jws-content)
  "Given the raw JWS JSON a request was sent with, decode the base64url protected
   header and return its \"nonce\" field."
  (let* ((jws (cl-json:decode-json-from-string jws-content))
         (protected64 (cdr (assoc :protected jws)))
         (protected (cl-json:decode-json-from-string
                     (flexi-streams:octets-to-string
                      (acme::base64url-decode protected64)
                      :external-format :utf-8))))
    (cdr (assoc :nonce protected))))

(test acme-badnonce-triggers-single-resigned-retry
  "RFC 8555 Section 6.5: a badNonce response triggers exactly one retry, the
   retried request re-signs its JWS protected header with the fresh Replay-Nonce
   from the badNonce response, and client-post returns the retry's success body."
  (let* ((client (%make-stub-acme-client))
         (calls nil)
         (fresh-nonce "fresh-nonce-from-badnonce-response")
         (acme::*http-request-function*
           (lambda (url &rest args)
             (push (list url (getf args :content)) calls)
             (if (= (length calls) 1)
                 ;; 1st call: badNonce problem document + a fresh Replay-Nonce.
                 (values "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"status\":400}"
                         400
                         (list (cons :replay-nonce fresh-nonce)))
                 ;; 2nd call: success.
                 (values "{\"status\":\"valid\"}"
                         200
                         (list (cons :replay-nonce "post-success-nonce")))))))
    ;; Pre-seed a (stale) nonce so no new-nonce GET is needed on the first attempt.
    (setf (acme::acme-client-nonce client) "stale-nonce")
    (multiple-value-bind (response status location)
        (acme::client-post client "https://acme.test/order" '(("field" . "value")))
      (declare (ignore location))
      (is (= 2 (length calls))
          "badNonce must cause exactly one retry (2 requests total)")
      (is (eql 200 status)
          "client-post must return the retried request's status")
      (is (equal "valid" (cdr (assoc :status response)))
          "client-post must return the retry's success body")
      ;; The retried (2nd) request must carry the FRESH nonce, not the stale one.
      (let ((retry-nonce (%protected-nonce (second (second (reverse calls))))))
        (is (string= fresh-nonce retry-nonce)
            "the retried request must re-sign with the fresh nonce")))))

(test acme-poll-status-tolerates-non-string-state
  "A NUMERIC :status in a response body (as an ACME problem document carries)
   must not crash client-poll-status: it is treated as non-terminal, polling
   continues, and a later valid state is returned."
  (let* ((client (%make-stub-acme-client))
         (calls 0)
         (acme::*http-request-function*
           (lambda (url &rest args)
             (declare (ignore url args))
             (incf calls)
             (if (= calls 1)
                 ;; A problem document: numeric state, must not crash the poll.
                 (values "{\"status\":400}" 400
                         (list (cons :replay-nonce "poll-nonce-a")))
                 ;; A real order body: terminal valid state.
                 (values "{\"status\":\"valid\"}" 200
                         (list (cons :replay-nonce "poll-nonce-b")))))))
    (setf (acme::acme-client-nonce client) "seed-nonce")
    (let (result-state)
      (finishes
        (multiple-value-bind (response state)
            (acme::client-poll-status client "https://acme.test/order"
                                      :max-attempts 5 :delay 0)
          (declare (ignore response))
          (setf result-state state)))
      (is (eq :valid result-state)
          "polling must recover past a numeric state and return :valid"))))

(defun run-acme-client-tests ()
  "Run the ACME client regression suite.  Returns T if all tests pass."
  (format t "~&=== Running pure-tls ACME Client Tests ===~%~%")
  (run! 'acme-client-tests))
