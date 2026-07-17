(define-public (add-supply (current uint) (delta uint))
  (let ((next (+ current delta)))
    (asserts! (>= next current) (err u400))
    (ok next)))
