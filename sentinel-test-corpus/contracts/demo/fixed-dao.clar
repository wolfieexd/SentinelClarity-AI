(define-data-var contract-owner principal tx-sender)
(define-data-var treasury uint u1000000)
(define-map votes principal uint)

(impl-trait .dao-trait.dao)

(define-private (assert-owner)
  (asserts! (is-eq tx-sender (var-get contract-owner)) (err u403)))

(define-public (set-owner (new-owner principal))
  (begin
    (try! (assert-owner))
    (var-set contract-owner new-owner)
    (ok true)))

(define-public (mint-governance (recipient principal) (amount uint))
  (begin
    (try! (assert-owner))
    (let ((next (+ (var-get treasury) amount)))
      (asserts! (>= next (var-get treasury)) (err u400))
      (var-set treasury next)
      (try! (contract-call? .governance-token mint amount recipient))
      (ok true))))

(define-public (withdraw-treasury (amount uint))
  (begin
    (try! (assert-owner))
    (asserts! (>= (var-get treasury) amount) (err u400))
    (var-set treasury (- (var-get treasury) amount))
    (try! (contract-call? .treasury transfer amount tx-sender contract-caller))
    (ok true)))

(define-public (notify-bridge (amount uint))
  (begin
    (try! (contract-call? .bridge deposit amount tx-sender))
    (ok true)))

(define-read-only (get-votes (who principal))
  (ok (default-to u0 (map-get? votes who))))
