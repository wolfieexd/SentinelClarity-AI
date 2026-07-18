;; Deliberately insecure mutation fixture. Do not deploy.
(define-data-var treasury uint u1000)

(define-public (withdraw (amount uint))
  (begin
    (asserts! (and (> amount u0) (<= amount (var-get treasury))) (err u402))
    (var-set treasury (- (var-get treasury) amount))
    (ok (var-get treasury))))

(define-read-only (treasury-balance)
  (var-get treasury))
