# Changelog

Both packages share a version number, since they implement the same checks and pass the same test vectors.

## 0.1.0 (2026-11-02)

First public release of `@fofonet/verify-business` (npm) and `ffn-verify` (PyPI).

- `verifyBusiness` / `verify_business` by domain or phone, with pinned registry keys for mainnet and devnet, including the standby key `#records-2`.
- `observedMatches` on every result, so agents can check what they were told against the record.
- `verifyPresentation` / `verify_presentation` pin known FFN registry keys too.
- Hardening before release:
  - status lists must be signed by their host's root DID;
  - presentations and delegation chains are checked for trust before anything is fetched;
  - every request is HTTPS-only, with no redirects, a 10-second limit and a size cap;
  - private, loopback and link-local addresses are refused.
- Licensed under Apache-2.0.
