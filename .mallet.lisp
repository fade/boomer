(:mallet-config
 (:extends :default)

 ;; Sequential LET* for binding blocks is a deliberate idiom here, not an
 ;; oversight. Keeping the form uniform means a binding can start referencing an
 ;; earlier one without churning LET into LET* and back, which is noise in the
 ;; diff and tells a reader nothing. Style, not correctness.
 (:disable :needless-let*)

 ;; An eval reached by unknowable input is a hard error, so I raise this rule to
 ;; :error and let it refuse the commit outright. Legitimate uses exist and are
 ;; rare; the way to keep one is a mallet:suppress directive at the call site
 ;; giving the reason it is safe there, which a later reader can check. A global
 ;; severity nobody re-reads cannot be checked.
 (:enable :no-eval :severity :error)

 ;; Not in the :default preset, so it has to be asked for. It marks places where
 ;; a bare ERROR raises SIMPLE-ERROR instead of a condition this library defines,
 ;; which matters for a TLS implementation: a caller that cannot distinguish a
 ;; protocol failure from a programming mistake cannot decide whether to retry,
 ;; alert, or abort the connection. Held at :info because the conversion is not
 ;; done, and a rule that fails a build the code cannot yet satisfy gets switched
 ;; off rather than fixed.
 (:enable :error-without-custom-condition :severity :info)

 ;; Test code answers to a different standard than the library. A test that
 ;; wraps a deliberately malformed input in IGNORE-ERRORS is doing exactly its
 ;; job, and an unused binding in a fixture is often there to document the shape
 ;; of the thing under test.
 (:path "test/"
        (:disable :no-ignore-errors)
        (:disable :unused-variables))

 ;; Vendored or generated test vectors are not ours to reformat.
 (:path "test/vectors/"
        (:disable :trailing-whitespace)
        (:disable :missing-final-newline)))
