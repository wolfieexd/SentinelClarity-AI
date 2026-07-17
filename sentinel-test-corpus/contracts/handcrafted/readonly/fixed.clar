(define-data-var total uint u0)

(define-read-only (get-total)
  (ok (var-get total)))
