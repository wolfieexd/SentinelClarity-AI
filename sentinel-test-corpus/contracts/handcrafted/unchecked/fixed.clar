(define-public (pay (amount uint))
  (begin
    (try! (contract-call? .token transfer amount tx-sender contract-caller))
    (ok true)))
