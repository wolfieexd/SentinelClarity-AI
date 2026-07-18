(define-data-var owner principal tx-sender)

(define-public (withdraw (amount uint))
  (begin
    (asserts! (is-eq tx-sender (var-get owner)) (err u401))
    (stx-transfer? amount tx-sender tx-sender)))
