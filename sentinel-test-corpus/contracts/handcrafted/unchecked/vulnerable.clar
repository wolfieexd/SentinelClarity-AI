(define-public (pay (amount uint))
  (begin
    (contract-call? .token transfer amount tx-sender contract-caller)
    (ok true)))
