(define-data-var contract-owner principal tx-sender)
(define-data-var treasury uint u1000000)
(define-map votes principal uint)

(impl-trait .dao-trait.dao)

(define-public (set-owner (new-owner principal))
  (begin
    (var-set contract-owner new-owner)
    (ok true)))

(define-public (mint-governance (recipient principal) (amount uint))
  (begin
    (var-set treasury (+ (var-get treasury) amount))
    (contract-call? .governance-token mint amount recipient)
    (ok true)))

(define-public (withdraw-treasury (amount uint))
  (begin
    (contract-call? .treasury transfer amount tx-sender contract-caller)
    (var-set treasury (- (var-get treasury) amount))
    (ok true)))

(define-public (notify-bridge (amount uint))
  (begin
    (contract-call? .bridge deposit amount tx-sender)
    (ok true)))

(define-read-only (get-votes (who principal))
  (begin
    (map-set votes who u1)
    (ok (default-to u0 (map-get? votes who)))))
