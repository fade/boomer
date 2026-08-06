;;; test/network-tests.lisp --- Live network validation tests
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Network tests for TLS 1.3 connections against major sites.

(in-package #:boomer/test)

(def-suite network-tests
  :description "Live TLS 1.3 connection tests")

(in-suite network-tests)

;;;; Connection Helper

(defun try-tls-connect (hostname &key (port 443) (verify boomer:+verify-required+) context)
  "Attempt TLS connection. Returns :success or an error keyword.
   On failure, prints error details to help with debugging."
  (let ((socket nil))
    (unwind-protect
        (handler-case
            (progn
              (setf socket (usocket:socket-connect hostname port
                                                   :element-type '(unsigned-byte 8)))
              (let ((tls (if context
                             (boomer:make-tls-client-stream
                              (usocket:socket-stream socket)
                              :hostname hostname :verify verify :context context)
                             (boomer:make-tls-client-stream
                              (usocket:socket-stream socket)
                              :hostname hostname :verify verify))))
                ;; TLS handshake succeeded - that's all we need to verify
                (close tls)
                :success))
          (boomer:tls-certificate-error (e)
            (format t "~&  [~A] cert-error: ~A~%" hostname e)
            :cert-error)
          (boomer:tls-verification-error (e)
            (format t "~&  [~A] verify-error: ~A~%" hostname e)
            :verify-error)
          (boomer:tls-handshake-error (e)
            (format t "~&  [~A] handshake-error: ~A~%" hostname e)
            :handshake-error)
          (boomer:tls-error (e)
            (format t "~&  [~A] tls-error: ~A~%" hostname e)
            :tls-error)
          (error (e)
            (format t "~&  [~A] other-error: ~A~%" hostname e)
            :other-error))
      (when socket (ignore-errors (usocket:socket-close socket))))))

;;;; TLS 1.3 Connection Tests (Major Sites)

(test connect-google
  "Connect to google.com"
  (is (eql (try-tls-connect "www.google.com") :success)))

(test connect-cloudflare
  "Connect to cloudflare.com"
  (is (eql (try-tls-connect "www.cloudflare.com") :success)))

(test connect-github
  "Connect to github.com"
  (is (eql (try-tls-connect "github.com") :success)))

(test connect-mozilla
  "Connect to mozilla.org"
  (is (eql (try-tls-connect "www.mozilla.org") :success)))

(test connect-amazon
  "Connect to amazon.com"
  (is (eql (try-tls-connect "www.amazon.com") :success)))

#+windows
(defun %make-empty-trust-context ()
  "Create a context that forces native Windows verification (no CA bundle)."
  (let ((ctx (boomer:make-tls-context :verify-mode boomer:+verify-required+
                                        :auto-load-system-ca nil)))
    (setf (boomer::tls-context-trust-store ctx)
          (boomer::make-trust-store :certificates nil))
    ctx))

#+windows
(test connect-google-windows-native
  "Connect to google.com using Windows CryptoAPI verification"
  (let ((ctx (%make-empty-trust-context))
        (boomer:*use-windows-certificate-store* t))
    (is (eql (try-tls-connect "www.google.com" :context ctx) :success))))

;;;; CRL Tests (moved from certificate-tests - these require network access)

(test crl-parsing
  "Test parsing a CRL file"
  ;; Fetch and parse a real CRL from Google
  (let ((google-cdp-uri "http://c.pki.goog/wr2/oBFYYahzgVI.crl"))
    (let ((crl (boomer::fetch-crl google-cdp-uri)))
      (when crl  ; May fail if network unavailable
        (is (> (boomer::crl-version crl) 0) "CRL should have a version")
        (is (boomer::crl-issuer crl) "CRL should have an issuer")
        (is (boomer::crl-this-update crl) "CRL should have thisUpdate")
        (is (boomer::crl-valid-p crl) "CRL should be currently valid")
        (is (listp (boomer::crl-revoked-certificates crl))
            "Revoked certificates should be a list")))))

(test crl-cache
  "Test CRL caching functionality"
  (boomer::clear-crl-cache)
  ;; Cache a mock entry
  (let ((test-uri "http://test.example.com/test.crl"))
    ;; No entry initially
    (is (null (boomer::get-cached-crl test-uri))
        "Cache should be empty initially")
    ;; Test caching with real CRL fetch
    (let ((google-uri "http://c.pki.goog/wr2/oBFYYahzgVI.crl"))
      (boomer::clear-crl-cache)
      (let ((crl1 (boomer::fetch-crl google-uri)))
        (when crl1
          (let ((crl2 (boomer::fetch-crl google-uri)))
            (is (eq crl1 crl2) "Second fetch should return cached CRL")))))))

(test crl-revocation-check
  "Test certificate revocation checking"
  ;; Test with a real certificate - should be :valid or :unknown (not :revoked)
  (let* ((socket (usocket:socket-connect "google.com" 443 :element-type '(unsigned-byte 8)))
         (tls nil))
    (unwind-protect
        (progn
          (setf tls (boomer:make-tls-client-stream
                     (usocket:socket-stream socket)
                     :sni-hostname "google.com"
                     :verify boomer:+verify-none+))
          (let* ((hs (boomer::tls-stream-handshake tls))
                 (chain (boomer::client-handshake-peer-certificate-chain hs))
                 (cert (first chain))
                 (issuer (second chain)))
            ;; Test with signature verification (requires issuer cert)
            (when issuer
              (let ((status (boomer::check-certificate-revocation
                             cert :issuer-cert issuer)))
                (is (member status '(:valid :unknown))
                    "Google certificate should not be revoked (with signature verification)")))
            ;; Test without signature verification (backward compatibility)
            (let ((status (boomer::check-certificate-revocation
                           cert :verify-signature nil)))
              (is (member status '(:valid :unknown))
                  "Google certificate should not be revoked (without signature verification)"))))
      (when tls (close tls))
      (usocket:socket-close socket))))

(test crl-signature-verification
  "Test CRL signature verification"
  ;; Fetch a CRL and verify its signature
  (let* ((socket (usocket:socket-connect "google.com" 443 :element-type '(unsigned-byte 8)))
         (tls nil))
    (unwind-protect
        (progn
          (setf tls (boomer:make-tls-client-stream
                     (usocket:socket-stream socket)
                     :sni-hostname "google.com"
                     :verify boomer:+verify-none+))
          (let* ((hs (boomer::tls-stream-handshake tls))
                 (chain (boomer::client-handshake-peer-certificate-chain hs))
                 (cert (first chain))
                 (issuer (second chain)))
            (when (and issuer (boomer::certificate-crl-distribution-points cert))
              (let* ((cdp-uri (first (boomer::certificate-crl-distribution-points cert)))
                     (crl (boomer::fetch-crl cdp-uri)))
                (when crl
                  ;; Verify the CRL signature
                  (is (boomer::verify-crl-signature crl issuer)
                      "CRL signature should verify against issuer certificate")
                  ;; Verify CRL issuer matches
                  (is (boomer::crl-issuer-matches-p crl cert)
                      "CRL issuer should match certificate issuer"))))))
      (when tls (close tls))
      (usocket:socket-close socket))))

;;;; Test Runner

(defun run-network-tests ()
  "Run network validation tests (requires internet)."
  (format t "~&Running TLS 1.3 network tests...~%~%")
  (run! 'network-tests))
