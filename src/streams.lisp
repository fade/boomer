;;; streams.lisp --- TLS Stream Implementation
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Implements TLS streams using Gray streams.

(in-package #:boomer)

;;;; TLS Stream Class

(defclass tls-stream (trivial-gray-stream-mixin
                      fundamental-binary-input-stream
                      fundamental-binary-output-stream)
  ((underlying-stream
    :initarg :stream
    :reader tls-stream-underlying-stream
    :documentation "The underlying TCP stream.")
   (record-layer
    :accessor tls-stream-record-layer
    :documentation "The TLS record layer.")
   (handshake
    :accessor tls-stream-handshake
    :documentation "The handshake state (after completion).")
   (input-buffer
    :initform (make-octet-vector 0)
    :accessor tls-stream-input-buffer
    :documentation "Buffer for decrypted data not yet read.")
   (input-position
    :initform 0
    :accessor tls-stream-input-position
    :documentation "Current position in input buffer.")
   (output-buffer
    :accessor tls-stream-output-buffer
    :documentation "Buffer for data to be encrypted and sent.")
   (output-position
    :initform 0
    :accessor tls-stream-output-position
    :documentation "Current position in output buffer.")
   (closed
    :initform nil
    :accessor tls-stream-closed-p
    :documentation "Whether the stream has been closed.")
   (spent
    :initform nil
    :reader tls-stream-spent-p
    :documentation "Whether this stream's transport and ciphers have been handed to
    an adopted record layer.  Distinct from CLOSED: closed says the connection is
    over, spent says it is alive and belongs to something else now.

    Readable by anyone and writable by nobody.  The mark is not a preference, it
    is a record of where the connection went, and clearing it would not bring
    any of it back.")
   (cancel-monitor-cleanup
    :initform nil
    :reader tls-stream-cancel-monitor-cleanup
    :documentation "Function that releases the close-on-cancel monitor watching
    the transport, or NIL when the stream was built without a cancel context.
    Held for the life of the stream rather than released once the handshake is
    done, because the monitor is the only thing that can interrupt a data-phase
    read already parked in the transport.

    Readable but not writable from outside, for the same reason as SPENT: which
    transport this stream may still close is not something a caller should be
    able to talk it out of.  SET-TLS-STREAM-CANCEL-MONITOR-CLEANUP is the only
    writer.")
   (close-callback
    :initarg :close-callback
    :initform nil
    :accessor tls-stream-close-callback)
   (warning-alert-count
    :initform 0
    :accessor tls-stream-warning-alert-count
    :documentation "Count of consecutive warning alerts received. Reset on app data.")
   (key-update-count
    :initform 0
    :accessor tls-stream-key-update-count
    :documentation "Count of KeyUpdate messages received. Used to prevent DoS.")
   (empty-record-count
    :initform 0
    :accessor tls-stream-empty-record-count
    :documentation "Count of consecutive empty records. Used to prevent DoS.")
   (handshake-message-buffer
    :initform nil
    :accessor tls-stream-handshake-message-buffer
    :documentation "Buffer for reassembling handshake messages that span records or are coalesced."))

  (:documentation "A TLS-encrypted stream."))

(defclass tls-client-stream (tls-stream)
  ()
  (:documentation "A TLS client stream."))

(defclass tls-server-stream (tls-stream)
  ()
  (:documentation "A TLS server stream."))

(defmethod initialize-instance :after ((stream tls-stream) &key
                                                            (buffer-size *default-buffer-size*)
                                                            &allow-other-keys)
  (setf (tls-stream-output-buffer stream)
        (make-octet-vector buffer-size)))

;;;; Ownership

;;; Adoption hands a record layer the stream's ciphers and its transport, and
;;; both go across by reference.  What is left behind is a stream object that
;;; still has accessors for all of it and no longer owns any of it, so the
;;; question every entry point has to ask first is whether it is still the owner
;;; of what it is about to use.

(defun check-tls-stream-unspent (stream operation)
  "Refuse OPERATION unless STREAM still owns its transport and its ciphers.

   OPERATION names the entry point for the report, so a caller reading the error
   can see which call it was rather than only that one of them was refused."
  (when (tls-stream-spent-p stream)
    (error 'tls-stream-spent :operation operation)))

(defun mark-tls-stream-spent (stream)
  "Record that STREAM's transport and its ciphers now belong to a record layer.

   This is not exported, so it is no part of the public API and no public name
   clears the mark.  Inside BOOMER it is the one place that sets it, which keeps
   the handover the only thing that does.

   A stream that has been marked and then unmarked is not a stream that got its
   connection back: it is a second user of one socket and one pair of sequence
   numbers, and the write side of that repeats a nonce the layer has already
   spent."
  (setf (slot-value stream 'spent) t)
  stream)

(defun set-tls-stream-cancel-monitor-cleanup (stream release)
  "Record RELEASE as what takes the close-on-cancel monitor off STREAM's transport.

   RELEASE is NIL once the monitor has been let go, which is what makes releasing
   twice a no-op rather than a second call into a monitor that is already gone."
  (setf (slot-value stream 'cancel-monitor-cleanup) release))

(defun release-cancel-monitor (stream)
  "Release the close-on-cancel monitor watching STREAM's transport, if it has one.

   Called when the transport stops being STREAM's to close, whether because the
   connection is over or because it was handed to somebody else.  Harmless to
   call more than once, and on a stream that never had a monitor."
  (let ((release (tls-stream-cancel-monitor-cleanup stream)))
    (when release
      (set-tls-stream-cancel-monitor-cleanup stream nil)
      (funcall release)))
  nil)

;;;; Stream Methods

(defmethod stream-element-type ((stream tls-stream))
  '(unsigned-byte 8))

(defmethod open-stream-p ((stream tls-stream))
  (not (tls-stream-closed-p stream)))

(defmethod close ((stream tls-stream) &key abort)
  (unless (tls-stream-closed-p stream)
    ;; A spent stream shuts down as a stream object and does nothing to the
    ;; connection.  The write cipher and the transport belong to the record
    ;; layer that took them: encrypting a close_notify would spend a sequence
    ;; number the layer is still counting from, and closing the transport would
    ;; end a connection its new owner is still using.  Neither is this stream's
    ;; to do, and the caller closing what it is holding should not have to know
    ;; that.
    (unless (tls-stream-spent-p stream)
      ;; Flush pending output unless aborting
      (unless abort
        (force-output stream))
      ;; Send close_notify alert and flush to ensure it's sent before closing
      (unless abort
        (handler-case
            (progn
              (record-layer-write-alert (tls-stream-record-layer stream)
                                        +alert-level-warning+
                                        +alert-close-notify+)
              (force-output (tls-stream-underlying-stream stream)))
          (error () nil)))  ; Ignore errors during shutdown
      ;; Close underlying stream (ignore errors - peer may have already closed)
      (handler-case
          (close (tls-stream-underlying-stream stream) :abort abort)
        (error () nil)))
    ;; Mark as closed
    (setf (tls-stream-closed-p stream) t)
    ;; The monitor exists to interrupt I/O that is already blocked, so it is
    ;; released only once there is no I/O left for it to interrupt.  Releasing
    ;; it any earlier would leave a data-phase read unreachable by cancellation,
    ;; and leaving it armed would let a later cancellation reach a transport
    ;; this stream is finished with.
    (release-cancel-monitor stream)
    ;; Call close callback
    (when (tls-stream-close-callback stream)
      (funcall (tls-stream-close-callback stream) stream)))
  t)

;;;; Input Methods

(defun tls-stream-get-key-schedule (stream)
  "Get the key schedule from the stream's handshake."
  (let ((hs (tls-stream-handshake stream)))
    (typecase hs
      (client-handshake (client-handshake-key-schedule hs))
      (server-handshake (server-handshake-key-schedule hs)))))

(defun tls-stream-get-cipher-suite (stream)
  "Get the cipher suite from the stream's handshake."
  (let ((hs (tls-stream-handshake stream)))
    (typecase hs
      (client-handshake (client-handshake-selected-cipher-suite hs))
      (server-handshake (server-handshake-selected-cipher-suite hs)))))

(defun tls-stream-is-client-p (stream)
  "Check if this is a client stream."
  (client-handshake-p (tls-stream-handshake stream)))

(defun tls-stream-process-new-session-ticket (stream nst)
  "Process a NewSessionTicket message, caching it for session resumption."
  (let ((hs (tls-stream-handshake stream)))
    ;; Only process on client side
    (when (client-handshake-p hs)
      (let ((resumption-secret (client-handshake-resumption-master-secret hs))
            (cipher-suite (client-handshake-selected-cipher-suite hs))
            (hostname (client-handshake-hostname hs)))
        (when (and resumption-secret hostname)
          (process-new-session-ticket nst resumption-secret cipher-suite hostname
                                      (client-handshake-verified-hostname hs)))))))

(defun tls-stream-process-key-update (stream key-update)
  "Process a KeyUpdate message, updating read keys and responding if requested."
  ;; Check for too many key updates (DoS prevention)
  (incf (tls-stream-key-update-count stream))
  (when (> (tls-stream-key-update-count stream) +max-key-updates+)
    (error 'tls-error :message ":TOO_MANY_KEY_UPDATES:"))
  ;; RFC 8446 Section 4.6.3: request_update must be 0 or 1
  ;; "If an implementation receives any other value, it MUST terminate
  ;;  the connection with an illegal_parameter alert."
  (let ((request-update (key-update-request-update key-update)))
    (unless (or (= request-update +key-update-not-requested+)
                (= request-update +key-update-requested+))
      (record-layer-write-alert (tls-stream-record-layer stream)
                                +alert-level-fatal+
                                +alert-illegal-parameter+)
      (error 'tls-error
             :message (format nil "Invalid KeyUpdate request_update value: ~D" request-update))))
  (let* ((ks (tls-stream-get-key-schedule stream))
         (cipher-suite (tls-stream-get-cipher-suite stream))
         (is-client (tls-stream-is-client-p stream)))
    ;; Update the sender's traffic secret (our read keys)
    ;; For client: sender is server, so update server application traffic secret
    ;; For server: sender is client, so update client application traffic secret
    (if is-client
        ;; We're client, received from server - update server app secret
        (setf (key-schedule-server-application-traffic-secret ks)
              (key-schedule-update-traffic-secret
               (key-schedule-server-application-traffic-secret ks)
               cipher-suite))
        ;; We're server, received from client - update client app secret
        (setf (key-schedule-client-application-traffic-secret ks)
              (key-schedule-update-traffic-secret
               (key-schedule-client-application-traffic-secret ks)
               cipher-suite)))
    ;; Install new read keys (from the sender's traffic secret)
    (multiple-value-bind (key iv)
        (if is-client
            (key-schedule-derive-server-traffic-keys ks :application)  ; client reads server
            (key-schedule-derive-client-traffic-keys ks :application)) ; server reads client
      (record-layer-install-keys (tls-stream-record-layer stream)
                                 :read key iv cipher-suite))
    ;; If update was requested, send our own KeyUpdate
    (when (= (key-update-request-update key-update) +key-update-requested+)
      (tls-stream-send-key-update stream :request-update nil))))

(defun tls-stream-send-key-update (stream &key (request-update nil))
  "Send a KeyUpdate message and update our write keys.
   REQUEST-UPDATE if true, asks the peer to also update their keys."
  (let* ((ks (tls-stream-get-key-schedule stream))
         (cipher-suite (tls-stream-get-cipher-suite stream))
         (is-client (tls-stream-is-client-p stream))
         (msg (make-key-update
               :request-update (if request-update
                                   +key-update-requested+
                                   +key-update-not-requested+)))
         (msg-bytes (serialize-key-update msg))
         (handshake-msg (wrap-handshake-message +handshake-key-update+ msg-bytes)))
    ;; Send the KeyUpdate message and flush immediately
    ;; This ensures the peer receives our response before we try to read more
    (record-layer-write (tls-stream-record-layer stream)
                        +content-type-handshake+ handshake-msg)
    (force-output (tls-stream-underlying-stream stream))
    ;; Update our traffic secret (write keys)
    (if is-client
        ;; We're client, updating our write keys
        (setf (key-schedule-client-application-traffic-secret ks)
              (key-schedule-update-traffic-secret
               (key-schedule-client-application-traffic-secret ks)
               cipher-suite))
        ;; We're server, updating our write keys
        (setf (key-schedule-server-application-traffic-secret ks)
              (key-schedule-update-traffic-secret
               (key-schedule-server-application-traffic-secret ks)
               cipher-suite)))
    ;; Install new write keys (from our own traffic secret)
    (multiple-value-bind (key iv)
        (if is-client
            (key-schedule-derive-client-traffic-keys ks :application)  ; client writes with client keys
            (key-schedule-derive-server-traffic-keys ks :application)) ; server writes with server keys
      (record-layer-install-keys (tls-stream-record-layer stream)
                                 :write key iv cipher-suite))))

(defun tls-stream-fill-buffer (stream)
  "Read more data from the record layer into the input buffer."
  (handler-case
      (multiple-value-bind (content-type data)
          (record-layer-read (tls-stream-record-layer stream))
        (case content-type
          (#.+content-type-application-data+
           ;; Check for empty records (DoS prevention)
           (cond ((zerop (length data))
                 (incf (tls-stream-empty-record-count stream))
                 (when (> (tls-stream-empty-record-count stream) +max-empty-records+)
                   (error 'tls-error :message ":TOO_MANY_EMPTY_FRAGMENTS:"))
                 ;; Recursively try for more data
                 (tls-stream-fill-buffer stream))
      (t
                 ;; Reset counters on non-empty application data
                 (setf (tls-stream-warning-alert-count stream) 0)
                 (setf (tls-stream-empty-record-count stream) 0)
                 (setf (tls-stream-input-buffer stream) data)
                 (setf (tls-stream-input-position stream) 0))))
          (#.+content-type-alert+
           ;; process-alert will error on most alerts, but returns nil for
           ;; user_canceled warnings which should be ignored
           (process-alert data (tls-stream-record-layer stream))
           ;; If we get here, the alert was ignored (user_canceled)
           ;; Track consecutive warning alerts to prevent DoS
           (incf (tls-stream-warning-alert-count stream))
           (when (> (tls-stream-warning-alert-count stream) +max-warning-alerts+)
             (record-layer-write-alert (tls-stream-record-layer stream)
                                       +alert-level-fatal+
                                       +alert-unexpected-message+)
             (error 'tls-error :message ":TOO_MANY_WARNING_ALERTS:"))
           ;; Recursively try for more data
           (tls-stream-fill-buffer stream))
          (#.+content-type-handshake+
           ;; Post-handshake messages (e.g., NewSessionTicket, KeyUpdate)
           ;; TLS 1.3 allows handshake messages to span records or multiple
           ;; messages to share one record, so we must use the reassembly buffer.
           (when (zerop (length data))
             (record-layer-write-alert (tls-stream-record-layer stream)
                                       +alert-level-fatal+
                                       +alert-decode-error+)
             (error 'tls-decode-error
                    :message ":DECODE_ERROR: Zero-length handshake record"))
           ;; Append incoming data to the reassembly buffer
           (setf (tls-stream-handshake-message-buffer stream)
                 (handshake-buffer-append
                  (tls-stream-handshake-message-buffer stream) data))
           ;; Post-handshake messages (KeyUpdate, NewSessionTicket) are small;
           ;; reject over-large advertised lengths before buffering more.
           ;; Certificate messages are never legitimate here, so the plain
           ;; cap applies to all message types.
           (check-handshake-buffer-size
            (tls-stream-handshake-message-buffer stream)
            (tls-stream-record-layer stream)
            :max-body-size *max-handshake-message-size*)
           ;; Process all complete handshake messages in the buffer
           (loop while (handshake-buffer-has-complete-message-p
                        (tls-stream-handshake-message-buffer stream))
                 do (multiple-value-bind (message-bytes remaining)
                        (handshake-buffer-extract-message
                         (tls-stream-handshake-message-buffer stream))
                      (setf (tls-stream-handshake-message-buffer stream) remaining)
                      (let ((msg (parse-handshake-message message-bytes)))
                        (case (handshake-message-type msg)
                          (#.+handshake-key-update+
                           (tls-stream-process-key-update stream (handshake-message-body msg)))
                          (#.+handshake-new-session-ticket+
                           (tls-stream-process-new-session-ticket stream (handshake-message-body msg)))
                          (otherwise
                           nil)))))
           ;; Recursively try to get more data
           (tls-stream-fill-buffer stream))
          (otherwise
           (record-layer-write-alert (tls-stream-record-layer stream)
                                     +alert-level-fatal+
                                     +alert-unexpected-message+)
           (error 'tls-error :message (format nil ":UNEXPECTED_RECORD: Unexpected content type: ~D" content-type)))))
    ;; Handle record overflow - send alert and re-signal
    (tls-record-overflow (e)
      (handler-case
          (record-layer-write-alert (tls-stream-record-layer stream)
                                    +alert-level-fatal+
                                    +alert-record-overflow+)
        (error () nil))  ; Ignore errors during alert send
      (error e))
    ;; Handle MAC verification failure - send alert and re-signal
    (tls-mac-error (e)
      (handler-case
          (record-layer-write-alert (tls-stream-record-layer stream)
                                    +alert-level-fatal+
                                    +alert-bad-record-mac+)
        (error () nil))  ; Ignore errors during alert send
      (error e))))

(defun tls-stream-buffer-remaining (stream)
  "Return the number of bytes remaining in the input buffer."
  (- (length (tls-stream-input-buffer stream))
     (tls-stream-input-position stream)))

(defmethod stream-read-byte ((stream tls-stream))
  (check-tls-stream-unspent stream "reading a byte")
  ;; Check request context for deadline/cancellation
  (let ((record-layer (tls-stream-record-layer stream)))
    (when record-layer
      (check-tls-context)))
  (when (tls-stream-closed-p stream)
    (return-from stream-read-byte :eof))
  ;; Refill buffer if empty
  (when (zerop (tls-stream-buffer-remaining stream))
    (handler-case
        (tls-stream-fill-buffer stream)
      (tls-connection-closed ()
        (return-from stream-read-byte :eof))))
  ;; Read from buffer
  (if (plusp (tls-stream-buffer-remaining stream))
      (prog1 (aref (tls-stream-input-buffer stream)
                   (tls-stream-input-position stream))
        (incf (tls-stream-input-position stream)))
      :eof))

(defmethod stream-read-sequence ((stream tls-stream) sequence start end &key)
  (check-tls-stream-unspent stream "reading a sequence")
  ;; Check request context for deadline/cancellation
  (let ((record-layer (tls-stream-record-layer stream)))
    (when record-layer
      (check-tls-context)))
  (when (tls-stream-closed-p stream)
    (return-from stream-read-sequence start))
  (let ((pos start)
        (first-read t))  ; Track if this is the first read
    (loop while (< pos end)
          do (progn
               ;; Refill buffer if needed
               (when (zerop (tls-stream-buffer-remaining stream))
                 ;; After first successful read, don't block if no data available
                 ;; This prevents deadlock when peer is waiting for response
                 (when (and (not first-read)
                            (not (listen (tls-stream-underlying-stream stream))))
                   (return-from stream-read-sequence pos))
                 (handler-case
                     (tls-stream-fill-buffer stream)
                   (tls-connection-closed ()
                     (return-from stream-read-sequence pos))))
               ;; Copy from buffer
               (let* ((remaining (tls-stream-buffer-remaining stream))
                      (to-copy (min remaining (- end pos))))
                 (when (zerop to-copy)
                   (return-from stream-read-sequence pos))
                 (replace sequence (tls-stream-input-buffer stream)
                          :start1 pos
                          :end1 (+ pos to-copy)
                          :start2 (tls-stream-input-position stream))
                 (incf pos to-copy)
                 (incf (tls-stream-input-position stream) to-copy)
                 (setf first-read nil))))  ; Mark that we've read some data
    pos))

(defmethod stream-listen ((stream tls-stream))
  (or (plusp (tls-stream-buffer-remaining stream))
      (listen (tls-stream-underlying-stream stream))))

;;;; Handing a finished connection to an adopted record layer

;;; The handshake runs blocking, on a thread, through the Gray stream above.
;;; When the connection is handed to an event loop for its data phase, the
;;; record layer takes over ownership of inbound plaintext, because a loop
;;; reader has no thread and no dynamic extent to keep that state on and needs
;;; it resident on the connection instead.  The Gray stream keeps its own input
;;; buffer for its own phase, where a thread and a stack are exactly what it
;;; has.  Two buffers, because the two phases hold state in different places.
;;;
;;; This lives on the stream side rather than in the record layer because only
;;; the stream side knows what a Gray stream is.  The record layer is given
;;; octets and an offset and stays free of any notion of where they came from.

(defun tls-stream-detach-input-plaintext (stream)
  "Take the decrypted octets STREAM has buffered but not yet handed to a reader.

   Returns the vector holding them and the index of the first one, or NIL and
   zero when nothing is outstanding.  STREAM is left with an empty input buffer,
   so afterwards the octets exist in one place and can be delivered once.

   What is outstanding is the tail from TLS-STREAM-INPUT-POSITION to the end of
   TLS-STREAM-INPUT-BUFFER, never the whole buffer.  The part in front of the
   position is what the application has already read.  Passing the whole buffer
   on would deliver that part a second time and passing nothing would drop the
   tail, and either one reaches the peer as a run of application octets that
   does not match what was sent.  That surfaces as the peer breaking protocol,
   with nothing pointing back at the handover, so the position travels with the
   vector rather than being flattened away by copying the tail out."
  (let ((buffer (tls-stream-input-buffer stream))
        (position (tls-stream-input-position stream)))
    (setf (tls-stream-input-buffer stream) (make-octet-vector 0)
          (tls-stream-input-position stream) 0)
    (if (< position (length buffer))
        (values buffer position)
        (values nil 0))))

(defun adopt-record-layer-from-tls-stream (stream &rest keys)
  "Build a record layer for the data phase from the finished blocking STREAM.

   This is the only way to obtain a record layer, so everything a caller has to
   know before driving one is stated here.

   The live AEAD ciphers, the transport and the plaintext STREAM has buffered
   but not yet handed out all move across, and STREAM is left holding no inbound
   plaintext.

   The inbound plaintext cannot be supplied by the caller, because supplying it
   and taking it from STREAM are two answers to the same question and there is
   no reading of the connection in which both are right.

   STREAM is left spent, because everything it would need in order to read, to
   write or to close now belongs to the returned layer.  Any later use of it
   signals TLS-STREAM-SPENT rather than acting on state it no longer owns.  A
   handover that fails leaves STREAM exactly as it was and usable, since nothing
   took what it is holding.

   The returned layer is not thread-safe, and nothing in it checks.  One
   connection's layer belongs to one thread at a time.  The ordinary arrangement
   crosses a thread boundary exactly once: the thread that ran the handshake
   calls this, publishes the layer to the thread that will drive the connection
   from then on, and never touches it again.  That publication has to be made
   safely by the caller, because the layer offers no lock, no ownership check
   and no way to notice that two threads are advancing the same sequence
   numbers.

   The layer sends no alerts.  It owns no stream to send one on, so a protocol
   fault reaches the caller as a signalled condition and stops there.  A caller
   that does not then send the alert itself leaves a peer that sent something
   invalid with no way to tell why the connection ended, which is the difference
   between a diagnosable failure and a hang.  The alert level and description
   constants are exported for that purpose.

   Those faults are not all one class.  TLS-RECORD-ERROR covers what goes wrong
   with a record, which is the group worth answering with an alert.  Using this
   stream after the handover signals TLS-STREAM-SPENT, which is a mistake about
   who owns the connection and is not under TLS-RECORD-ERROR.  A handler meant
   to catch everything should be on TLS-ERROR.

   A known limitation, reasoned from the code and not yet reproduced against a
   peer: a post-handshake message that arrived alongside the last message of the
   handshake, or that was still being reassembled when the handover happened, is
   not carried across and is lost.  A NewSessionTicket arriving that way is
   legal and routine, and losing one presents later as resumption quietly not
   working rather than as anything to do with the handover.  A caller for which
   resumption matters should read a connection that produced no ticket as
   unremarkable rather than as evidence about the peer.

   KEYS set the new layer's own budgets and its cancellation context.  The
   accepted ones are:

     :MAX-SEND-FRAGMENT   the largest plaintext the layer will put in one
                          outgoing record.
     :REQUEST-CONTEXT     an optional cl-cancel context, so a caller can cancel
                          or time out work the layer does on the transport.
     :MAX-IN-CIPHERTEXT   the layer's own budget for each of the four record
     :MAX-IN-PLAINTEXT    buffers.  They default to the protocol ceilings, which
     :MAX-OUT-PLAINTEXT   is what the layer has always accepted; a caller
     :MAX-OUT-CIPHERTEXT  holding many connections at once can set them lower to
                          spend less memory per connection.

   Everything else the layer needs is taken from STREAM, and one rule covers all
   of it: what the stream supplies cannot also be passed here.  :READ-CIPHER,
   :WRITE-CIPHER, :CIPHER-SUITE, :IN-PLAINTEXT and :IN-PLAINTEXT-START are
   therefore refused outright.  Each is refused rather than quietly dropped,
   because a caller that believes it supplied a cipher and did not would be
   wrong about the one thing this handover exists to get right."
  (loop for key in keys by #'cddr
        when (member key '(:read-cipher :write-cipher :cipher-suite
                           :in-plaintext :in-plaintext-start))
          do (error "adopt-record-layer-from-tls-stream: ~S comes from STREAM and cannot be passed in."
                    key))
  (let ((layer (tls-stream-record-layer stream))
        (buffer (tls-stream-input-buffer stream))
        (position (tls-stream-input-position stream))
        (adopted nil))
    (multiple-value-bind (plaintext plaintext-start)
        (tls-stream-detach-input-plaintext stream)
      (unwind-protect
           (setf adopted
                 (apply #'adopt-record-layer
                        (tls-stream-underlying-stream stream)
                        :read-cipher (record-layer-read-cipher layer)
                        :write-cipher (record-layer-write-cipher layer)
                        :cipher-suite (record-layer-cipher-suite layer)
                        :in-plaintext plaintext
                        :in-plaintext-start plaintext-start
                        keys))
        (unless adopted
          ;; No layer was built, so nothing took the plaintext and STREAM is
          ;; still its only holder.  Put it back where the detach found it,
          ;; rather than leaving a stream that a reader can still use but that
          ;; has quietly lost octets the peer sent.
          (setf (tls-stream-input-buffer stream) buffer
                (tls-stream-input-position stream) position))))
    ;; Last, and only now that the layer exists.  Marking any earlier would spend
    ;; a stream that a failed handover leaves as the only owner of the connection.
    (mark-tls-stream-spent stream)
    ;; The monitor goes with the transport it was watching.  The returned layer
    ;; is driven by being fed octets and never parks in a read, so there is no
    ;; blocked I/O left for a monitor to interrupt, and an armed one would only
    ;; be able to close a transport that now belongs to the layer.
    (release-cancel-monitor stream)
    adopted))

;;;; Output Methods

(defmethod stream-write-byte ((stream tls-stream) byte)
  (check-tls-stream-unspent stream "writing a byte")
  (when (tls-stream-closed-p stream)
    (error 'tls-error :message "Cannot write to closed stream"))
  (let ((buf (tls-stream-output-buffer stream))
        (pos (tls-stream-output-position stream)))
    (setf (aref buf pos) byte)
    (incf (tls-stream-output-position stream))
    ;; Flush if buffer is full
    (when (= (tls-stream-output-position stream) (length buf))
      (force-output stream)))
  byte)

(defmethod stream-write-sequence ((stream tls-stream) sequence start end &key)
  (check-tls-stream-unspent stream "writing a sequence")
  (when (tls-stream-closed-p stream)
    (error 'tls-error :message "Cannot write to closed stream"))
  (loop while (< start end)
        do (let* ((buf (tls-stream-output-buffer stream))
                  (pos (tls-stream-output-position stream))
                  (space (- (length buf) pos))
                  (to-copy (min space (- end start))))
             (replace buf sequence
                      :start1 pos
                      :start2 start
                      :end2 (+ start to-copy))
             (incf (tls-stream-output-position stream) to-copy)
             (incf start to-copy)
             ;; Flush if buffer is full
             (when (= (tls-stream-output-position stream) (length buf))
               (force-output stream))))
  sequence)

(defmethod stream-force-output ((stream tls-stream))
  (check-tls-stream-unspent stream "flushing output")
  (when (plusp (tls-stream-output-position stream))
    ;; Pass the pending region of the output buffer directly; the record layer
    ;; bounds it with :end, so no subseq copy of the payload is made per flush.
    (record-layer-write-application-data
     (tls-stream-record-layer stream)
     (tls-stream-output-buffer stream)
     :end (tls-stream-output-position stream))
    (setf (tls-stream-output-position stream) 0))
  (force-output (tls-stream-underlying-stream stream)))

(defmethod stream-finish-output ((stream tls-stream))
  (stream-force-output stream))

;;;; Stream Accessors

(defun tls-peer-certificate (stream)
  "Return the peer's certificate, if available.
   Returns an x509-certificate structure (already parsed)."
  (let ((hs (tls-stream-handshake stream)))
    (when hs
      (typecase hs
        (client-handshake (client-handshake-peer-certificate hs))
        (server-handshake (server-handshake-peer-certificate hs))))))

(defun tls-peer-certificate-chain (stream)
  "Return the peer's full certificate chain, if available.
   Returns a list of x509-certificate structures (leaf first)."
  (let ((hs (tls-stream-handshake stream)))
    (when hs
      (typecase hs
        (client-handshake (client-handshake-peer-certificate-chain hs))
        (server-handshake (server-handshake-peer-certificate-chain hs))))))

(defun tls-selected-alpn (stream)
  "Return the negotiated ALPN protocol, if any."
  (let ((hs (tls-stream-handshake stream)))
    (when hs
      (typecase hs
        (client-handshake (client-handshake-selected-alpn hs))
        (server-handshake (server-handshake-selected-alpn hs))))))

(defun tls-cipher-suite (stream)
  "Return the negotiated cipher suite."
  (let ((hs (tls-stream-handshake stream)))
    (when hs
      (typecase hs
        (client-handshake (client-handshake-selected-cipher-suite hs))
        (server-handshake (server-handshake-selected-cipher-suite hs))))))

(defun tls-version (stream)
  "Return the TLS version (always 1.3 for this implementation)."
  (declare (ignore stream))
  +tls-1.3+)

(defun tls-client-hostname (stream)
  "Return the client's SNI hostname (server-side only)."
  (let ((hs (tls-stream-handshake stream)))
    (when (server-handshake-p hs)
      (server-handshake-client-hostname hs))))

(defun tls-request-key-update (stream &key (request-peer-update t))
  "Request a TLS 1.3 key update on STREAM.
   This updates the sending keys immediately and optionally requests
   the peer to also update their keys.

   REQUEST-PEER-UPDATE - If true (default), the peer must respond with
                         their own KeyUpdate message. If false, only our
                         sending keys are updated."
  (tls-stream-send-key-update stream :request-update request-peer-update))

(defun tls-ech-accepted-p (stream)
  "Return T if ECH (Encrypted Client Hello) was used and accepted by the server.
   Returns NIL if ECH was not used, was rejected, or this is a server stream."
  (let ((hs (tls-stream-handshake stream)))
    (when (client-handshake-p hs)
      (client-handshake-ech-accepted hs))))

;;;; Stream Creation

(defun make-tls-client-stream (socket &key
                                        hostname
                                        sni-hostname
                                        (context (ensure-default-context))
                                        (verify (tls-context-verify-mode context))
                                        alpn-protocols
                                        client-certificate
                                        client-key
                                        ech-configs
                                        (ech-enabled t)
                                        close-callback
                                        external-format
                                        (buffer-size *default-buffer-size*)
                                        max-send-fragment
                                        request-context)
  "Create a TLS client stream over SOCKET.

   SOCKET - The underlying TCP stream or socket.
   HOSTNAME - Server hostname for SNI and verification.
   SNI-HOSTNAME - Override hostname for SNI only (no verification).
   CONTEXT - TLS context for configuration.
   VERIFY - Certificate verification mode.
   ALPN-PROTOCOLS - List of ALPN protocol names to offer.
   CLIENT-CERTIFICATE - Certificate for client authentication (mTLS).
   CLIENT-KEY - Private key for client authentication (mTLS).
   ECH-CONFIGS - ECH configurations for Encrypted Client Hello (from DNS or manual).
                 Can be raw bytes (ECHConfigList) or parsed ECH-CONFIG structures.
   ECH-ENABLED - Enable ECH when configs available (default T).
   CLOSE-CALLBACK - Function called when stream is closed.
   EXTERNAL-FORMAT - If non-NIL, wrap in a flexi-stream.
   BUFFER-SIZE - Size of I/O buffers.
   MAX-SEND-FRAGMENT - Maximum plaintext size for outgoing records.
   REQUEST-CONTEXT - Optional cl-cancel context for timeout/cancellation support.

   Returns the TLS stream, or a flexi-stream if EXTERNAL-FORMAT specified."
  (let* ((stream (make-instance 'tls-client-stream
                                :stream socket
                                :close-callback close-callback
                                :buffer-size buffer-size))
         (record-layer (make-record-layer socket
                                          :max-send-fragment (or max-send-fragment
                                                                 +max-record-size+)
                                          :request-context request-context))
         ;; Set up automatic socket closure on context cancellation
         (cancel-monitor (setup-close-on-cancel request-context socket))
         (trust-store (tls-context-trust-store context))
         ;; SNI uses sni-hostname if provided, otherwise hostname
         (sni-name (or sni-hostname hostname))
         ;; Load client certificate chain from file if path provided
         ;; Handle: list of certs, single cert object, file path, or nil
         (loaded-certs (cond
                         ((null client-certificate) nil)
                         ((listp client-certificate) client-certificate)
                         ((x509-certificate-p client-certificate) (list client-certificate))
                         ((stringp client-certificate) (load-certificate-chain client-certificate))
                         ((pathnamep client-certificate) (load-certificate-chain client-certificate))
                         (t nil)))
         ;; Split: first cert is the client cert, rest are chain certs
         (client-cert (when loaded-certs (first loaded-certs)))
         (chain-certs (when loaded-certs (rest loaded-certs)))
         ;; Load client private key from file if path provided
         (private-key (cond
                        ((or (null client-key) (stringp client-key) (pathnamep client-key))
                         (let ((key-source (or client-key
                                               (when (stringp client-certificate) client-certificate)
                                               (when (pathnamep client-certificate) client-certificate))))
                           (when key-source
                             (load-private-key key-source))))
                        (t client-key))))  ; Already an Ironclad key object
    (setf (tls-stream-record-layer stream) record-layer)
    (set-tls-stream-cancel-monitor-cleanup stream cancel-monitor)
    ;; Perform handshake (CertificateVerify is verified during handshake)
    ;; Skip hostname verification if only sni-hostname is provided (no hostname)
    ;; Parse ECH configs if raw bytes provided
    (let ((parsed-ech-configs
            (when ech-configs
              (if (and (typep ech-configs '(simple-array (unsigned-byte 8) (*)))
                       (> (length ech-configs) 2))
                  ;; Raw ECHConfigList bytes - parse them
                  (parse-ech-config-list ech-configs)
                  ;; Already parsed or list of configs
                  (if (listp ech-configs)
                      ech-configs
                      (list ech-configs))))))
      (let ((hs (perform-client-handshake
                  record-layer
                  :hostname sni-name
                  :alpn-protocols (or alpn-protocols
                                      (tls-context-alpn-protocols context))
                  :verify-mode verify
                  :trust-store trust-store
                  :skip-hostname-verify (and sni-hostname (null hostname))
                  :client-certificate client-cert
                  :client-private-key private-key
                  :client-certificate-chain chain-certs
                  :ech-configs parsed-ech-configs
                  :ech-enabled ech-enabled
                  :hostname-policy (tls-context-hostname-policy context))))
        (setf (tls-stream-handshake stream) hs)
        ;; Verify certificate chain and hostname if verification enabled
        (when (and (member verify (list +verify-peer+ +verify-required+))
                   (client-handshake-peer-certificate hs))
          (let ((cert (client-handshake-peer-certificate hs))
                (chain (client-handshake-peer-certificate-chain hs)))
            ;; Verify hostname - only if hostname (not just sni-hostname) was provided
            (when hostname
              (verify-hostname cert hostname :policy (tls-context-hostname-policy context)))
            ;; Verify certificate chain for both +verify-peer+ and +verify-required+
            ;; (+verify-peer+ means "verify if presented" - servers always present certs)
            (when chain
              ;; On Windows/macOS with native verification enabled, verify even without trust-store
              ;; (they use their own trusted root stores)
              (let ((trusted-roots (when trust-store
                                     (trust-store-certificates trust-store))))
                (verify-certificate-chain chain trusted-roots
                                          :now (get-universal-time)
                                          :hostname hostname
                                          :purpose :server-auth)))
            ;; Record the verified identity when this full handshake proved it
            ;; under +verify-required+ (hostname supplied, hostname + chain
            ;; verified without error above).  A NewSessionTicket read later on
            ;; this stream carries this forward so a resumption can rely on the
            ;; original handshake's authentication (RFC 8446 Section 4.2.11).
            (when (and (= verify +verify-required+) hostname chain)
              (setf (client-handshake-verified-hostname hs) hostname))))))
    ;; Wrap with flexi-stream if external-format specified
    (if external-format
        (flexi-streams:make-flexi-stream stream :external-format external-format)
        stream)))

(defun make-tls-server-stream (socket &key
                                        (context (ensure-default-context))
                                        certificate
                                        key
                                        (verify +verify-none+)
                                        trust-store
                                        alpn-protocols
                                        sni-callback
                                        certificate-provider
                                        close-callback
                                        external-format
                                        (buffer-size *default-buffer-size*)
                                        max-send-fragment
                                        request-context)
  "Create a TLS server stream over SOCKET.

   SOCKET - The underlying TCP stream or socket.
   CONTEXT - TLS context for configuration.
   CERTIFICATE - Certificate chain (list of x509-certificate) or path to PEM file.
   KEY - Private key (Ironclad key object) or path to PEM file.
   VERIFY - Client certificate verification mode (+verify-none+, +verify-peer+, +verify-required+).
   TRUST-STORE - Trust store for verifying client certificates.
   ALPN-PROTOCOLS - List of ALPN protocol names the server supports.
   SNI-CALLBACK - Function called with the client's requested hostname.
                  Should return (VALUES certificate-chain private-key) for that host,
                  or NIL to use the default certificate/key.
   CERTIFICATE-PROVIDER - Function called with (hostname alpn-list) before cert selection.
                          Should return (VALUES cert-chain key selected-alpn) to override
                          certificate and ALPN, or NIL to use defaults. For ACME TLS-ALPN-01.
   CLOSE-CALLBACK - Function called when stream is closed.
   EXTERNAL-FORMAT - If non-NIL, wrap in a flexi-stream.
   BUFFER-SIZE - Size of I/O buffers.
   MAX-SEND-FRAGMENT - Maximum plaintext size for outgoing records.
   REQUEST-CONTEXT - Optional cl-cancel context for timeout/cancellation support.

   Returns the TLS stream, or a flexi-stream if EXTERNAL-FORMAT specified."
  (let* ((stream (make-instance 'tls-server-stream
                                :stream socket
                                :close-callback close-callback
                                :buffer-size buffer-size))
         (record-layer (make-record-layer socket
                                          :max-send-fragment (or max-send-fragment
                                                                 +max-record-size+)
                                          :request-context request-context))
         ;; Set up automatic socket closure on context cancellation
         (cancel-monitor (setup-close-on-cancel request-context socket))
         ;; Get certificate chain (from parameter, context, or file)
         (cert-chain (cond
                       ((listp certificate) certificate)
                       ((stringp certificate) (load-certificate-chain certificate))
                       ((pathnamep certificate) (load-certificate-chain certificate))
                       (t (tls-context-certificate-chain context))))
         ;; Get private key (from parameter, context, or file)
         (private-key (cond
                        ((or (null key) (stringp key) (pathnamep key))
                         (let ((key-source (or key
                                               (when (stringp certificate) certificate)
                                               (when (pathnamep certificate) certificate))))
                           (if key-source
                               (load-private-key key-source)
                               (tls-context-private-key context))))
                        (t key)))  ; Already an Ironclad key object
         ;; Get trust store for client certificate verification
         ;; Use explicit trust-store parameter if provided
         ;; Do NOT fall back to context trust store - server-side client cert verification
         ;; should only use what's explicitly provided. This allows +verify-required+ to
         ;; require a certificate without verifying its chain (e.g., for testing).
         (client-trust-store trust-store)
         ;; Get ALPN protocols
         (alpn (or alpn-protocols (tls-context-alpn-protocols context))))
    ;; Validate we have certificate and key
    (unless cert-chain
      (error 'tls-error :message "Server requires a certificate chain"))
    (unless private-key
      (error 'tls-error :message "Server requires a private key"))
    (setf (tls-stream-record-layer stream) record-layer)
    (set-tls-stream-cancel-monitor-cleanup stream cancel-monitor)
    ;; Perform server handshake
    (let ((hs (perform-server-handshake
               record-layer
               cert-chain
               private-key
               :alpn-protocols alpn
               :verify-mode verify
               :trust-store client-trust-store
               :sni-callback sni-callback
               :certificate-provider certificate-provider)))
      (setf (tls-stream-handshake stream) hs))
    ;; Wrap with flexi-stream if external-format specified
    (if external-format
        (flexi-streams:make-flexi-stream stream :external-format external-format)
        stream)))

;;;; Convenience Macros

(defmacro with-tls-client-stream ((var socket &rest args) &body body)
  "Execute BODY with VAR bound to a TLS client stream over SOCKET.
   The stream is automatically closed when BODY exits (normally or abnormally).

   ARGS are passed to MAKE-TLS-CLIENT-STREAM (e.g., :hostname, :verify).

   Example:
     (with-tls-client-stream (tls socket :hostname \"example.com\")
       (write-sequence request tls)
       (read-response tls))"
  `(let ((,var (make-tls-client-stream ,socket ,@args)))
     (unwind-protect
         (progn ,@body)
       (close ,var))))

(defmacro with-tls-server-stream ((var socket &rest args) &body body)
  "Execute BODY with VAR bound to a TLS server stream over SOCKET.
   The stream is automatically closed when BODY exits (normally or abnormally).

   ARGS are passed to MAKE-TLS-SERVER-STREAM (e.g., :certificate, :key).

   Example:
     (with-tls-server-stream (tls client-socket :certificate cert :key key)
       (handle-request tls))"
  `(let ((,var (make-tls-server-stream ,socket ,@args)))
     (unwind-protect
         (progn ,@body)
       (close ,var))))
