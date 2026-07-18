(define-data-var owner principal tx-sender)

(define-public (withdraw (amount uint))
  (begin
    (asserts! (is-eq contract-caller (var-get owner)) (err u401))
    (stx-transfer? amount contract-caller contract-caller)))
