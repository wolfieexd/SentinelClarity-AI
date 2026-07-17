(define-map balances principal uint)

(define-public (withdraw (amount uint))
  (begin
    (contract-call? .token transfer amount tx-sender contract-caller)
    (map-set balances tx-sender u0)
    (ok true)))
