## 2025-05-19 - Crypto Rand Read Error Handling
**Vulnerability:** Ignored error return from `crypto/rand.Read`.
**Learning:** Even `crypto/rand` can fail (though rare). Ignoring the error can lead to zero-initialized buffers being used as "random" values, compromising security (predictable IDs).
**Prevention:** Always check the error return of `rand.Read` and handle it (propagate or panic depending on context).
