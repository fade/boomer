;;; anvil-client.lisp --- Simple TLS client for TLS-Anvil testing
;;;
;;; This is triggered by TLS-Anvil when testing our client implementation.

(require :asdf)

;; Load boomer from parent directory
(let ((boomer-dir (make-pathname :directory (butlast (pathname-directory *load-truename*) 2))))
  (push boomer-dir asdf:*central-registry*))

(asdf:load-system :boomer)
(require :usocket)

(defpackage #:anvil-client
  (:use #:cl)
  (:export #:connect))

(in-package #:anvil-client)

(defun connect (host port)
  "Connect to TLS server and perform simple exchange."
  (handler-case
      (let* ((socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)))
             (stream (usocket:socket-stream socket)))
        (unwind-protect
             (let ((tls-stream (boomer:make-tls-client-stream
                                stream
                                :hostname host
                                :verify nil)))  ; Don't verify for testing
               (unwind-protect
                    (progn
                      ;; Send some data
                      (write-sequence (babel:string-to-octets "hello from boomer") tls-stream)
                      (force-output tls-stream)
                      ;; Try to read response (with timeout)
                      (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
                        (handler-case
                            (let ((n (read-sequence buf tls-stream)))
                              (when (> n 0)
                                (format t "Received ~D bytes~%" n)))
                          (error () nil))))
                 (close tls-stream)))
          (usocket:socket-close socket)))
    (error (e)
      (format *error-output* "Connection error: ~A~%" e))))
