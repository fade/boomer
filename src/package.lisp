;;; package.lisp --- Package definitions for boomer
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>

(in-package #:cl-user)

(defpackage #:boomer
  (:use #:cl #:trivial-gray-streams)
  (:export
   ;; Stream creation
   #:make-tls-client-stream
   #:make-tls-server-stream
   #:with-tls-client-stream
   #:with-tls-server-stream

   ;; Context management
   #:make-tls-context
   #:tls-context-free
   #:with-tls-context
   #:*default-tls-context*

   ;; Stream class
   #:tls-stream
   #:tls-client-stream
   #:tls-server-stream

   ;; Stream accessors
   #:tls-peer-certificate
   #:tls-peer-certificate-chain
   #:tls-selected-alpn
   #:tls-cipher-suite
   #:tls-version
   #:tls-client-hostname
   #:tls-request-key-update

   ;; Certificate handling
   #:parse-certificate
   #:parse-certificate-from-file
   #:load-certificate-chain
   #:load-private-key
   #:certificate-subject-common-names
   #:certificate-fingerprint
   #:certificate-not-before
   #:certificate-not-after
   #:certificate-free
   #:verify-hostname

   ;; Hostname-verification policy
   #:hostname-policy
   #:make-hostname-policy
   #:hostname-policy-allow-wildcards
   #:hostname-policy-allow-cn-fallback
   #:*general-hostname-policy*
   #:*strict-privacy-hostname-policy*

   ;; Crypto utilities
   #:random-bytes
   #:constant-time-equal
   #:zeroize
   #:with-zeroized-vector

   ;; Record padding (traffic analysis mitigation)
   #:*record-padding-policy*


   ;; Conditions
   #:tls-error
   #:tls-handshake-error
   #:tls-certificate-error
   #:tls-verification-error
   #:tls-alert-error
   #:tls-decode-error
   #:tls-record-overflow
   #:tls-context-cancelled
   #:tls-deadline-exceeded

   ;; Verification modes
   #:+verify-none+
   #:+verify-peer+
   #:+verify-required+

   ;; Alert codes
   #:+alert-close-notify+
   #:+alert-unexpected-message+
   #:+alert-bad-record-mac+
   #:+alert-record-overflow+
   #:+alert-handshake-failure+
   #:+alert-bad-certificate+
   #:+alert-certificate-revoked+
   #:+alert-certificate-expired+
   #:+alert-certificate-unknown+
   #:+alert-illegal-parameter+
   #:+alert-unknown-ca+
   #:+alert-decode-error+
   #:+alert-decrypt-error+
   #:+alert-protocol-version+
   #:+alert-insufficient-security+
   #:+alert-internal-error+
   #:+alert-user-canceled+
   #:+alert-missing-extension+
   #:+alert-unsupported-extension+
   #:+alert-unrecognized-name+

   ;; Cipher suites
   #:+tls-aes-128-gcm-sha256+
   #:+tls-aes-256-gcm-sha384+
   #:+tls-chacha20-poly1305-sha256+

   ;; Configuration
   #:*default-buffer-size*
   #:*default-verify-mode*
   #:*max-certificate-list-size*
   #:*max-handshake-message-size*

   ;; Session resumption
   #:*session-ticket-cache*
   #:*server-ticket-key*
   #:session-ticket-cache-clear

   ;; Platform-specific verification
   #:*use-windows-certificate-store*
   #+windows #:verify-certificate-chain-windows
   #:*use-macos-keychain*
   #+(or darwin macos) #:verify-certificate-chain-macos

   ;; Record engine: driving a finished connection from an event loop
   #:record-layer-feed-ciphertext
   #:record-layer-input-wanted
   #:record-layer-message-available-p
   #:record-layer-take-message
   #:record-layer-take-plaintext
   #:record-layer-plaintext-available
   #:record-layer-note-transport-eof
   #:record-layer-submit-plaintext
   #:record-layer-pending-output
   #:record-layer-ack-output
   #:adopt-record-layer-from-tls-stream

   ;; Record engine: what is left of a stream that has been handed over
   #:tls-stream-spent-p

   ;; Record engine: the faults it signals, and what they can be asked
   #:tls-record-error
   #:tls-record-error-content-type
   #:tls-plaintext-pending
   #:tls-plaintext-pending-available
   #:tls-output-in-flight
   #:tls-output-in-flight-outstanding
   #:tls-output-ack-overrun
   #:tls-output-ack-overrun-acknowledged
   #:tls-output-ack-overrun-outstanding
   #:tls-stream-spent
   #:tls-stream-spent-operation

   ;; Record content types, as returned by RECORD-LAYER-TAKE-MESSAGE and
   ;; accepted by RECORD-LAYER-SUBMIT-PLAINTEXT
   #:+content-type-change-cipher-spec+
   #:+content-type-alert+
   #:+content-type-handshake+
   #:+content-type-application-data+

   ;; Alert levels, for the alerts a caller of the record engine sends itself
   #:+alert-level-warning+
   #:+alert-level-fatal+

   ;; ECH (Encrypted Client Hello)
   #:tls-ech-accepted-p
   #:tls-ech-retry-error
   #:tls-ech-retry-error-configs
   #:parse-ech-config-list))
