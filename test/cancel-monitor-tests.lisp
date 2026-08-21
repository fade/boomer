;;; cancel-monitor-tests.lisp --- Release of the close-on-cancel transport monitor
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; A TLS stream built with a cancel context gets a monitor watching its
;;; transport, whose job is to close the socket underneath a read that is
;;; already blocked.  These tests cover when that monitor is released: not while
;;; the stream can still read, and not left armed over a transport the stream no
;;; longer owns.

(in-package :boomer/test)

(def-suite cancel-monitor-tests
    :description "Release of the close-on-cancel monitor watching a TLS transport")

(in-suite cancel-monitor-tests)

(defun count-cancel-monitors ()
  "Number of live monitor threads watching a stream for cancellation."
  (count "cancel-stream-monitor" (bt:all-threads)
         :key #'bt:thread-name :test #'equal))

(defun wait-until (predicate &key (timeout 5) (interval 0.01))
  "Poll PREDICATE until it returns true, or until TIMEOUT seconds have passed.

   Returns the last value PREDICATE produced, so the caller asserts on the
   condition itself rather than on the fact that waiting finished.  A thread
   asked to stop takes an unpredictable moment to do so, and a fixed sleep is
   either longer than the suite can afford or short enough to fail on a loaded
   machine."
  (let ((deadline (+ (get-internal-real-time)
                     (round (* timeout internal-time-units-per-second)))))
    (loop for value = (funcall predicate)
          when value
            return value
          when (> (get-internal-real-time) deadline)
            return value
          do (sleep interval))))

(defun call-with-loopback-tls-client (request-context function
                                      &key (wrap-transport #'identity))
  "Call FUNCTION with a client TLS stream connected to a loopback server.

   The stream is built with REQUEST-CONTEXT, and FUNCTION also receives the
   client socket so it can look at the transport directly.  The server holds the
   connection open until FUNCTION returns.

   WRAP-TRANSPORT is handed the socket stream and returns what the TLS stream is
   built over, which is how a caller puts an instrument between the stream and
   the socket."
  (let ((listener (usocket:socket-listen "127.0.0.1" 0
                                         :reuse-address t
                                         :element-type '(unsigned-byte 8)))
        (release (bt2:make-semaphore))
        (server-thread nil)
        (client-socket nil))
    (unwind-protect
         (let ((port (usocket:get-local-port listener)))
           (setf server-thread
                 (bt2:make-thread
                  (lambda ()
                    ;; The server exists to give the client something to hand
                    ;; shake with.  Whatever it hits is the client's business to
                    ;; report, and a condition escaping here would only turn up
                    ;; as an unrelated thread dying.
                    (handler-case
                        (let ((peer (usocket:socket-accept listener
                                                           :element-type '(unsigned-byte 8))))
                          (unwind-protect
                               (progn
                                 (boomer:make-tls-server-stream
                                  (usocket:socket-stream peer)
                                  :certificate (test-cert-path "resumption-leaf.pem")
                                  :key (test-cert-path "resumption-leaf.key"))
                                 (bt2:wait-on-semaphore release :timeout 30))
                            (handler-case (usocket:socket-close peer)
                              (error () nil))))
                      (error () nil)))
                  :name "cancel-monitor-test-server"))
           (setf client-socket (usocket:socket-connect "127.0.0.1" port
                                                       :element-type '(unsigned-byte 8)))
           (funcall function
                    (boomer:make-tls-client-stream
                     (funcall wrap-transport (usocket:socket-stream client-socket))
                     :sni-hostname "localhost"
                     :verify boomer:+verify-none+
                     :request-context request-context)
                    client-socket))
      (bt2:signal-semaphore release)
      ;; Guarded one at a time, so a failure to shut one of these down still
      ;; leaves the others shut down.
      (when server-thread
        (handler-case (bt2:join-thread server-thread) (error () nil)))
      (when client-socket
        (handler-case (usocket:socket-close client-socket) (error () nil)))
      (handler-case (usocket:socket-close listener) (error () nil)))))

(defclass close-counting-transport (trivial-gray-streams:fundamental-binary-input-stream
                                    trivial-gray-streams:fundamental-binary-output-stream)
  ((target
    :initarg :target
    :reader close-counting-transport-target
    :documentation "The socket stream every operation is passed through to.")
   (close-count
    :initform 0
    :accessor close-counting-transport-close-count
    :documentation "How many times this transport has been asked to close."))
  (:documentation "A transport that counts the closes it is asked for.

   A socket ignores being closed a second time, so a socket cannot show whether a
   released monitor stayed off the transport or merely arrived too late to
   matter.  This can.  It is also a fair model of a real caller: the stream
   constructors take a stream rather than a socket, and a transport that hands a
   pooled connection back when it is closed does notice a second close arriving
   from a monitor for a stream that is finished with it."))

(defmethod stream-element-type ((transport close-counting-transport))
  '(unsigned-byte 8))

(defmethod trivial-gray-streams:stream-read-sequence
    ((transport close-counting-transport) sequence start end &key)
  (read-sequence sequence (close-counting-transport-target transport)
                 :start start :end end))

(defmethod trivial-gray-streams:stream-write-sequence
    ((transport close-counting-transport) sequence start end &key)
  (write-sequence sequence (close-counting-transport-target transport)
                  :start start :end end))

(defmethod trivial-gray-streams:stream-read-byte ((transport close-counting-transport))
  (read-byte (close-counting-transport-target transport) nil :eof))

(defmethod trivial-gray-streams:stream-write-byte ((transport close-counting-transport) byte)
  (write-byte byte (close-counting-transport-target transport)))

(defmethod trivial-gray-streams:stream-force-output ((transport close-counting-transport))
  (force-output (close-counting-transport-target transport)))

(defmethod trivial-gray-streams:stream-listen ((transport close-counting-transport))
  (listen (close-counting-transport-target transport)))

(defmethod close ((transport close-counting-transport) &key abort)
  ;; Counted before it is passed on, so a close the socket refuses is still a
  ;; close this transport was asked for.
  (incf (close-counting-transport-close-count transport))
  (handler-case (close (close-counting-transport-target transport) :abort abort)
    (error () nil))
  t)

(test closing-a-monitored-stream-is-safe-and-repeatable
  "Closing a watched stream neither fails nor minds being closed twice.

   This covers the trap the release has to stay clear of rather than the release
   itself.  Letting the monitor go means calling into cl-cancel from CLOSE, and
   an unguarded call there turns the join it performs into a failure of the close
   that asked for it, and a second close into a call on a monitor that is already
   gone.

   Nothing here says whether the monitor was actually released, and it cannot:
   the monitor exits when the context completes whether it was released or not,
   so the thread count returning to baseline says only that the context is done.
   MONITOR-RELEASED-WHEN-THE-STREAM-CLOSES is where that question is asked."
  (let ((baseline (count-cancel-monitors))
        (context (cl-cancel:with-cancel (cl-cancel:background))))
    (call-with-loopback-tls-client
     context
     (lambda (tls socket)
       (declare (ignore socket))
       (is (wait-until (lambda () (> (count-cancel-monitors) baseline)))
           "A stream built with a cancel context should be watched by a monitor.")
       (finishes (close tls))
       (finishes (close tls))
       (cl-cancel:cancel context)
       (is (wait-until (lambda () (= (count-cancel-monitors) baseline)))
           "No monitor thread should outlive the context it was watching.")))))

(test monitor-released-when-the-stream-closes
  "Closing a stream stops the monitor reaching the transport again.

   The transport counts the closes it is asked for, which is the only place the
   difference shows on this path.  CLOSE has already closed the transport by the
   time the monitor could act, so an unreleased monitor closes it a second time
   and a socket ignores that; the count does not."
  (let ((baseline (count-cancel-monitors))
        (context (cl-cancel:with-cancel (cl-cancel:background)))
        (transport nil))
    (call-with-loopback-tls-client
     context
     (lambda (tls socket)
       (declare (ignore socket))
       (is (wait-until (lambda () (> (count-cancel-monitors) baseline)))
           "A stream built with a cancel context should be watched by a monitor.")
       (close tls)
       (is (= 1 (close-counting-transport-close-count transport))
           "Closing the stream should close its transport once.")
       (cl-cancel:cancel context)
       ;; The monitor closes the transport before its thread returns, so a
       ;; thread count back at baseline is a sound point to read the count at:
       ;; whatever the monitor was going to do, it has already done.
       (is (wait-until (lambda () (= (count-cancel-monitors) baseline)))
           "No monitor thread should outlive the context it was watching.")
       (is (= 1 (close-counting-transport-close-count transport))
           "Cancelling afterwards must not reach the transport: the stream let
            the monitor go when it finished with it."))
     :wrap-transport (lambda (socket-stream)
                       (setf transport
                             (make-instance 'close-counting-transport
                                            :target socket-stream))))))

(test adopted-transport-keeps-its-monitor-off
  "Handing the transport to a record layer takes the monitor off it."
  (let ((baseline (count-cancel-monitors))
        (context (cl-cancel:with-cancel (cl-cancel:background))))
    (call-with-loopback-tls-client
     context
     (lambda (tls socket)
       (is (wait-until (lambda () (> (count-cancel-monitors) baseline)))
           "A stream built with a cancel context should be watched by a monitor.")
       (let ((transport (usocket:socket-stream socket)))
         (is (boomer::adopt-record-layer-from-tls-stream tls)
             "The handover should produce a record layer.")
         (cl-cancel:cancel context)
         (is (wait-until (lambda () (= (count-cancel-monitors) baseline)))
             "No monitor thread should outlive the context it was watching.")
         (is (open-stream-p transport)
             "Cancelling after the handover must leave the transport alone: it
              belongs to the record layer now, which is driven by being fed
              octets and never has a read for a monitor to interrupt."))))))
