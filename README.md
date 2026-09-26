# Dark DBC host-side cryptography spike

This is a feasibility test harness, not a deployable program. It uses the
versioned Solana ElGamal SDK and Token-2022 confidential-transfer
proof-generation helper to test low/high ciphertext combination, Pod public
key encoding, deterministic 2-of-3 Shamir arithmetic, candidate masked-inversion
arithmetic, test-only Chaum-Pedersen proofs for aggregate decryption shares,
aggregate ciphertext decryption, and bounded discrete-log recovery.

An in-process Token-2022 ProgramTest is also included. It initializes a
confidential-transfer mint and reads back the exact auditor-key bytes. The
fixture key comes from a known test scalar; it is not a DKG. This test does not
execute a confidential transfer or validate its proof-context flow.

The masked-inversion test is a centrally simulated arithmetic transcript, not
an MPC security test or DKG. The DLEQ test uses fixed nonces and does not
implement a production proof encoding, verifier, or nonce generator. The
harness does not implement the custom per-bid ZK commitment link, Token-2022
CPI, confidential-vault custody, Anchor, or DBC settlement. Passing tests do
not prove those blockers are solved.

The test dependency versions are pinned in `Cargo.toml` and `Cargo.lock`.
Token-2022 9.x uses Solana 2.x program types, so the in-process runtime is
version-aligned to Solana 2.3.13. The host proof-generation crate uses the
newer ElGamal SDK; the integration fixture converts the encoded public key
through the Token-2022 SDK type before mint initialization.

One result is especially important: the SDK maps an ElGamal secret scalar `s`
to public key `H / s`. Public keys created from Shamir shares therefore do not
interpolate to the aggregate key. A masked-inversion arithmetic simulation
shows how reshared products could derive shares of `1/s`, while retaining the
original shares of `s` for decryption. No maintained, audited Rust
implementation for this exact mapping was found, so a reviewed malicious-secure
distributed-inversion/DKG remains the next cryptographic gate. The ordinary
threshold-decryption fixture still uses the full test secret to construct its
key.

Run:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```