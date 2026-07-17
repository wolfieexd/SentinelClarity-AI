(define-map balances principal uint)

(define-public (withdraw (amount uint))
  (begin
    (map-set balances tx-sender u0)
    (try! (contract-call? .token transfer amount tx-sender contract-caller))
    (ok true)))
