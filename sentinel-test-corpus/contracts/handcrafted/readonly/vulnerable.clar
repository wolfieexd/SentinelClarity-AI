(define-data-var total uint u0)

(define-read-only (get-total)
  (begin
    (var-set total u1)
    (ok (var-get total))))
