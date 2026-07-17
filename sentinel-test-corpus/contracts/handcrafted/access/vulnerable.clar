(define-data-var owner principal tx-sender)

(define-public (set-owner (new-owner principal))
  (begin
    (var-set owner new-owner)
    (ok true)))
