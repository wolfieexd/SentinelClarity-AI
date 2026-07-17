(define-data-var owner principal tx-sender)

(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get owner)) (err u403))
    (var-set owner new-owner)
    (ok true)))
