;;; test/der-bounds-tests.lisp --- Malformed DER input tests
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Brian O'Reilly <fade@deepsky.com>
;;;
;;; Certificate cases are derived from test/certs/self-signed-valid.pem.
;;; Each malformed case must signal TLS-DECODE-ERROR within a time bound
;;; rather than exhausting the heap or the control stack. The fuzz run
;;; also accepts a clean parse.

(in-package #:boomer/test)

(in-suite certificate-tests)

(defparameter *malformed-der-source* "self-signed-valid.pem"
  "Fixture under test/certs/ that the malformed DER inputs are derived from.")

(defparameter *malformed-der-time-limit* 2
  "Seconds a single malformed DER parse may take before it counts as a hang.")

(defun malformed-der-source-bytes ()
  "Return a fresh copy of the DER bytes of *MALFORMED-DER-SOURCE*."
  (copy-seq (boomer::pem-decode
             (boomer::read-file-bytes (test-cert-path *malformed-der-source*))
             "CERTIFICATE")))

(defun der-octets (&rest parts)
  "Concatenate PARTS (octet sequences or single octets) into an octet vector."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0)))
    (dolist (part parts)
      (if (integerp part)
          (vector-push-extend part out)
          (loop for b across part do (vector-push-extend b out))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defmacro signals-decode-error-promptly (form &optional (label "input"))
  "Assert that FORM signals TLS-DECODE-ERROR within *MALFORMED-DER-TIME-LIMIT*."
  (let ((start (gensym "START")))
    `(let ((,start (get-internal-real-time)))
       (signals boomer:tls-decode-error ,form)
       (is (< (- (get-internal-real-time) ,start)
              (* *malformed-der-time-limit* internal-time-units-per-second))
           "~A took longer than ~D s" ,label *malformed-der-time-limit*))))

(test der-truncated-certificate-signals-decode-error
  "A certificate cut short at any point signals TLS-DECODE-ERROR."
  (let* ((der (malformed-der-source-bytes))
         (len (length der)))
    (dolist (cut (list 1 2 3 4 5 10 (floor len 2) (- len 1)))
      (signals-decode-error-promptly
       (boomer::parse-der (subseq der 0 cut))
       (format nil "~A truncated to ~D of ~D octets" *malformed-der-source* cut len)))))

(test der-overstated-outer-length-signals-decode-error
  "An outer SEQUENCE length larger than the input signals TLS-DECODE-ERROR."
  (let* ((der (malformed-der-source-bytes))
         (content-length (- (length der) 4)))
    ;; The fixture opens with 30 82 hi lo.
    (is (and (= (aref der 0) #x30) (= (aref der 1) #x82))
        "Fixture must open with a two-octet long-form SEQUENCE header")
    (dolist (declared (list (+ content-length 1) (+ content-length 1000) #xFFFF))
      (let ((bad (copy-seq der)))
        (setf (aref bad 2) (ldb (byte 8 8) declared)
              (aref bad 3) (ldb (byte 8 0) declared))
        (signals-decode-error-promptly
         (boomer::parse-der bad)
         (format nil "outer length ~D for ~D content octets" declared content-length))))))

(test der-long-form-length-with-many-octets-signals-decode-error
  "A length field with an excessive number of length octets signals TLS-DECODE-ERROR."
  (let* ((der (malformed-der-source-bytes))
         (body (subseq der 4))
         (n (length body)))
    ;; The correct value, padded with leading zeros to 127 length octets.
    (signals-decode-error-promptly
     (boomer::parse-der (der-octets #x30 #xFF
                                    (make-array 125 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)
                                    (ldb (byte 8 8) n) (ldb (byte 8 0) n)
                                    body))
     "zero-padded 127-octet length")
    ;; A 127-octet length of all ones.
    (signals-decode-error-promptly
     (boomer::parse-der (der-octets #x30 #xFF
                                    (make-array 127 :element-type '(unsigned-byte 8)
                                                    :initial-element #xFF)
                                    body))
     "127-octet all-ones length")
    ;; A nine-octet length on a primitive.
    (signals-decode-error-promptly
     (boomer::parse-der (der-octets #x04 #x89 1 0 0 0 0 0 0 0 0 body))
     "nine-octet length on OCTET STRING")))

(test der-deep-nesting-signals-decode-error
  "A certificate wrapped in 10,000 SEQUENCE headers signals TLS-DECODE-ERROR."
  (let* ((der (malformed-der-source-bytes))
         (levels 10000)
         (header-size 5)
         (out (make-array (+ (length der) (* levels header-size))
                          :element-type '(unsigned-byte 8)))
         (pos 0))
    ;; Each level is 30 83 xx xx xx, so every declared length is exact.
    (loop for level from levels above 0
          for inner = (+ (length der) (* (1- level) header-size))
          do (setf (aref out pos) #x30
                   (aref out (+ pos 1)) #x83
                   (aref out (+ pos 2)) (ldb (byte 8 16) inner)
                   (aref out (+ pos 3)) (ldb (byte 8 8) inner)
                   (aref out (+ pos 4)) (ldb (byte 8 0) inner))
             (incf pos header-size))
    (replace out der :start1 pos)
    (signals-decode-error-promptly (boomer::parse-der out)
                                   "10,000 nested SEQUENCE headers")))

(test der-long-form-tag-past-cap-signals-decode-error
  "A long-form tag with more continuation octets than the cap signals TLS-DECODE-ERROR."
  (let ((body (subseq (malformed-der-source-bytes) 4)))
    ;; Context-specific constructed, long-form tag of 16 octets.
    (signals-decode-error-promptly
     (boomer::parse-der (der-octets #xBF
                                    (make-array 15 :element-type '(unsigned-byte 8)
                                                   :initial-element #xFF)
                                    #x01 #x00 body))
     "16-octet long-form tag")))

(test der-empty-input-signals-decode-error
  "An empty octet vector signals TLS-DECODE-ERROR rather than returning NIL."
  (signals-decode-error-promptly
   (boomer::parse-der (boomer::make-octet-vector 0))
   "empty octet vector"))

(test der-trailing-octets-signal-decode-error
  "Octets after the top-level node signal TLS-DECODE-ERROR.
The certificate case is test/certs/self-signed-valid.pem with one octet appended."
  (signals-decode-error-promptly
   (boomer::parse-der (der-octets #x05 #x00 #xFF))
   "NULL node followed by FF")
  (let* ((source "self-signed-valid.pem")
         (der (boomer::pem-decode (boomer::read-file-bytes (test-cert-path source))
                                  "CERTIFICATE")))
    (is (typep (boomer::parse-der der) 'boomer::asn1-node)
        "~A must parse before the octet is appended" source)
    (signals-decode-error-promptly
     (boomer::parse-der (der-octets der #x00))
     (format nil "~A with one octet appended" source))))

(defun make-der-fuzz-prng (seed)
  "Return a function of N yielding a deterministic integer in [0, N) seeded by SEED."
  (let ((state seed))
    (lambda (n)
      (setf state (ldb (byte 64 0) (+ (* state 6364136223846793005)
                                      1442695040888963407)))
      (mod (ash state -33) n))))

(defun der-parse-outcome (bytes)
  "Parse BYTES; return :PARSED, :DECODE-ERROR, or the other condition signalled."
  (handler-case (progn (boomer::parse-der bytes) :parsed)
    (boomer:tls-decode-error () :decode-error)
    (error (e) e)))

(test der-random-input-signals-only-decode-error
  "Fixed-seed random and mutated inputs either parse or signal TLS-DECODE-ERROR.
Random octets can happen to be valid DER, so a successful parse is allowed;
any other condition, or a slow run, is a failure."
  (let* ((der (malformed-der-source-bytes))
         (rand (make-der-fuzz-prng 20261109))
         (start (get-internal-real-time))
         (outcomes nil)
         (failures nil))
    (flet ((try (bytes label)
             (let ((outcome (der-parse-outcome bytes)))
               (push outcome outcomes)
               (unless (member outcome '(:parsed :decode-error))
                 (push (format nil "~A: ~A" label outcome) failures)))))
      ;; Random octet strings of length 1 to 64.
      (dotimes (i 1000)
        (let ((bytes (boomer::make-octet-vector (1+ (funcall rand 64)))))
          (dotimes (j (length bytes))
            (setf (aref bytes j) (funcall rand 256)))
          (try bytes (format nil "random string ~D" i))))
      ;; The fixture with one to four octets overwritten.
      (dotimes (i 1000)
        (let ((bytes (copy-seq der)))
          (dotimes (k (1+ (funcall rand 4)))
            (setf (aref bytes (funcall rand (length bytes))) (funcall rand 256)))
          (try bytes (format nil "mutation ~D of ~A" i *malformed-der-source*)))))
    (is (null failures)
        "~D input(s) signalled something other than TLS-DECODE-ERROR, first: ~A"
        (length failures) (first (last failures)))
    (is (member :decode-error outcomes)
        "The fuzz run should include at least one rejected input")
    (is (< (- (get-internal-real-time) start)
           (* 10 *malformed-der-time-limit* internal-time-units-per-second))
        "2,000 fuzz inputs should parse or fail promptly")))
