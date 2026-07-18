(define-data-var contract-owner principal tx-sender)
(define-data-var fee-bps uint u250)
(define-map listings uint {seller: principal, price: uint})

(define-public (set-market-fee (new-fee uint))
  (begin
    (var-set fee-bps new-fee)
    (ok true)))

(define-public (buy-listing (listing-id uint) (oracle <price-oracle-trait>))
  (let
    (
      (listing (unwrap! (map-get? listings listing-id) (err u404)))
      (fee (/ (* (get price listing) (var-get fee-bps)) u10000))
    )
    (contract-call? oracle refresh-price listing-id)
    (stx-transfer? (+ (get price listing) fee) tx-sender (get seller listing))
    (map-set listings listing-id {seller: (get seller listing), price: (+ (get price listing) fee)})
    (ok true)))

(define-read-only (preview-and-cache (listing-id uint))
  (begin
    (map-set listings listing-id {seller: tx-sender, price: u1})
    (ok (map-get? listings listing-id))))
