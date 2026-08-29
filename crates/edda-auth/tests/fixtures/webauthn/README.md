# WebAuthn conformance vectors

These fixtures are consumed by `webauthn::tests::conformance` in
`crates/edda-auth/src/webauthn.rs` and gated in CI by the
`webauthn conformance vectors` job in `.github/workflows/ci.yml`.

## What's here

- `rs256_test_key.pkcs8.pem` — RustCrypto's own PKCS#8 RSA-2048 test key.
  Fixed so the RS256 vectors (and the `an_rs256_credential_round_trips`
  unit test) are deterministic and need no key generation at test time.

- `register_<alg>_accept.json` / `register_<alg>_crossorigin_reject.json`
  `authenticate_<alg>_accept.json` / `authenticate_<alg>_badsig_reject.json`
  for `alg ∈ {es256, ed25519, rs256}` — each freezes one complete ceremony
  at the byte level (the exact `clientDataJSON`, `attestationObject` /
  `authenticatorData` + `signature`, RP config, and expected accept/reject
  outcome). The consumer test mints a fresh ceremony token for the fixture's
  challenge (the token's HMAC secret is process-random, so it can't be
  committed) and then runs the real `finish_registration` /
  `finish_authentication` against the frozen bytes — so a future refactor of
  the CBOR parsing, the multi-algorithm dispatch, or any individual check
  cannot silently change what this verifier accepts.

## Regenerating

```
cargo test -p edda-auth -- --ignored regenerate_conformance_fixtures
```

Then review and commit the diff. ES256/EdDSA keys are random per run
(RS256 uses the fixed key above), so the bytes churn on every regeneration —
that is expected; the committed files are the artifact, not the RNG.

## Follow-up: real captured ceremonies

The vectors here are produced by Edda's own `FakeAuthenticator`. They catch
*regressions* (the verifier drifting from its own frozen behaviour) but not
a bug shared between the fake authenticator and the verifier. Real ceremony
captures from Chrome / Safari / Firefox + a hardware security key (plan
C1.e) should be added here as additional `*.json` fixtures once that
hardware is available for capture — the consumer test already handles any
number of fixtures.
