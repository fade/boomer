;;; debug-openssl.lisp - Debug script for OpenSSL test execution

(require :asdf)
(asdf:load-system :boomer/test)

;; Add debug tracing
(defvar *debug-keys* nil)

(let ((original-install-keys (symbol-function 'boomer::record-layer-install-keys)))
  (setf (symbol-function 'boomer::record-layer-install-keys)
        (lambda (layer direction key iv cipher-suite)
          (push (list direction
                      (copy-seq key)
                      (copy-seq iv)
                      (bt:current-thread))
                *debug-keys*)
          (funcall original-install-keys layer direction key iv cipher-suite))))

;; Run the test
(let* ((cnf-file (merge-pathnames "01-simple.cnf" boomer/test::*openssl-ssl-tests-dir*))
       (tests (boomer/test::load-openssl-tests cnf-file))
       (test-0 (find "0-default" tests :key #'boomer/test::openssl-test-name :test #'string=)))
  (multiple-value-bind (result message)
      (boomer/test::run-openssl-test test-0)
    (format t "~%Result: ~A~%Message: ~A~%" result message)))

;; Print captured keys
(format t "~%Captured key installations:~%")
(dolist (entry (reverse *debug-keys*))
  (destructuring-bind (direction key iv thread) entry
    (format t "  ~A (~A): key[0..7]=~A iv[0..7]=~A~%"
            direction
            (bt:thread-name thread)
            (subseq key 0 (min 8 (length key)))
            (subseq iv 0 (min 8 (length iv))))))
