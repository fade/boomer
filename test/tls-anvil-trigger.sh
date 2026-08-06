#!/bin/bash
# TLS-Anvil trigger script for boomer client testing
# This script is called by TLS-Anvil to trigger a boomer client connection

cd "$(dirname "$0")/.."

# Arguments passed by TLS-Anvil
HOST="${1:-localhost}"
PORT="${2:-4433}"

# Run boomer client
sbcl --noinform --non-interactive \
    --eval "(asdf:load-system :boomer :verbose nil)" \
    --eval "(asdf:load-system :usocket :verbose nil)" \
    --eval "
(handler-case
    (let ((socket (usocket:socket-connect \"$HOST\" $PORT :element-type '(unsigned-byte 8))))
      (unwind-protect
           (let ((tls-stream (boomer:make-tls-client-stream
                               (usocket:socket-stream socket)
                               :hostname \"$HOST\"
                               :verify boomer:+verify-none+)))
             ;; Try to read - TLS-Anvil may send data
             (handler-case
                 (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
                   (read-sequence buf tls-stream))
               (end-of-file () nil))
             (close tls-stream))
        (usocket:socket-close socket)))
  (error (e)
    (format *error-output* \"TLS error: ~A~%\" e)
    (sb-ext:exit :code 1)))" \
    2>&1
