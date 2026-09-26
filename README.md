# Dark DBC host-side cryptography spike

This is a feasibility test harness, not a deployable program. It uses the
versioned Solana ElGamal SDK and Token-2022 confidential-transfer
proof-generation helper to test low/high ciphertext combination, Pod public
key encoding, deterministic 2-of-3 Shamir arithmetic, candidate masked-inversion
arithmetic, test-only Chaum-Pedersen proofs for aggregate decryption shares,
aggregate ciphertext decryption, and bounded discrete-log recovery.

The separate `token-2022-program-test` harness initializes a
confidential-transfer mint in Solana ProgramTest and reads back the exact
auditor-key bytes. Its fixture key comes from a known test scalar; it is not a
DKG. This test does not execute a confidential transfer or validate its
proof-context flow. It is isolated from the default host-side suite because the
native Solana runtime exceeds this workspace's memory limit during compilation;
the test remains unverified until it completes on a larger runner.

The separate `token-2022-processor-test` invokes the Token-2022 processor
directly with in-memory `AccountInfo` values and a host syscall stub for
`Rent::get`. It passes 1/1 and confirms that the `InitializeMint2` processor
route accepts the SDK key and stores it in the confidential-transfer mint
extension. It is not ProgramTest: it does not validate actual runtime sysvar
loading, system-program account creation, CPI behavior, or a confidential
transfer proof context. Treat it as partial processor evidence only.

The masked-inversion test is a centrally simulated arithmetic transcript, not
an MPC security test or DKG. The DLEQ test uses fixed nonces and does not
implement a production proof encoding, verifier, or nonce generator. The
harness does not implement the custom per-bid ZK commitment link, Token-2022
CPI, confidential-vault custody, Anchor, or DBC settlement. Passing tests do
not prove those blockers are solved.

The host-side dependency versions are pinned in `Cargo.toml` and `Cargo.lock`;
the isolated ProgramTest dependencies have their own manifest and lockfile.
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

Verification status as of 2026-09-26: the default host-side suite passes 6/6
tests, `protocol-spike` passes 10/10, and the direct Token-2022 processor check
passes 1/1. Formatting checks pass for all four manifests; Clippy passes for
the root, `protocol-spike`, and `token-2022-processor-test` crates. ProgramTest
builds were attempted in the root package before isolation, serially with debug
info disabled and as a metadata-only check, but the operating system killed
`rustc` while compiling `libsecp256k1` before the test ran. ProgramTest runtime
initialization therefore remains unverified.

Run:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo test --manifest-path protocol-spike/Cargo.toml
cargo test --manifest-path token-2022-processor-test/Cargo.toml
cargo test --manifest-path token-2022-program-test/Cargo.toml
```

## Research notes

See `THRESHOLD_CRYPTO_REVIEW.md` for the source-linked candidate scan and the
go/no-go criteria before DBC settlement work.