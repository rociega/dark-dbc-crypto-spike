# Launch Shield workspace: DBC auction and cryptographic feasibility spikes

## Active target: sealed-bid Meteora DBC launch

The active product direction is the practical bonded commit–reveal anti-sniping
flow in [`launch-shield/README.md`](launch-shield/README.md): eight fixed-max
escrowed bids, an SP1 proof linking each hidden bid to its commitment, public
reveal after the window, one atomic DBC `swap2`, and pro-rata token claims.
This is deliberately not the private-claims mixer explored by older research
notes below. The Rust on-chain processor and proof relation now exist and their
host tests pass; the Groth16 proof producer, SBF build, validator/DBC transaction
tests, deployed DBC version match, and vkey hash are still unverified. Do not
treat the code as deployed or production-ready.

The material below records earlier feasibility spikes and remains useful
cryptographic research, but it is not the current launch design.

The root crate is a host-side feasibility test harness, not a deployable
program. It uses the
versioned Solana ElGamal SDK and Token-2022 confidential-transfer
proof-generation helper to test low/high ciphertext combination, equivalence
between that combined ciphertext and full-amount encryption with the
SDK-combined Pedersen opening, Pod public-key encoding, deterministic 2-of-3
Shamir arithmetic, candidate masked-inversion arithmetic, test-only
Chaum-Pedersen proofs for aggregate decryption shares, aggregate ciphertext
decryption, and bounded discrete-log recovery.

The `protocol-spike` also tests a fixed-depth-three Merkle-path helper and an
eight-slot nullifier registry. SHA-256 is used only as a test hash for the tree
plumbing; the production hash and circuit are unselected. These tests cover
transparent paths, incremental root updates, atomic host-side note/nullifier
registration, capacity, and one-time state changes, not private membership or
proof of note ownership.

The separate `token-2022-program-test` harness initializes a
confidential-transfer mint in Solana ProgramTest and reads back the exact
auditor-key bytes. Its fixture key comes from a known test scalar; it is not a
DKG. This test does not execute a confidential transfer or validate its
proof-context flow. It is isolated from the default host-side suite because the
native Solana runtime exceeds this workspace's memory limit during compilation;
the test remains unverified until it completes on a larger runner.

The separate `token-2022-processor-test` harness passes 4/4. One test invokes
the Token-2022 processor with in-memory `AccountInfo` values and a host
`Rent::get` syscall stub; it confirms the `InitializeMint2` route accepts the
SDK key and stores it in the confidential-transfer mint extension. A second
inspects the CPI-compatible `inner_transfer` builder and confirms it carries
the exact supplied auditor ciphertext pair and proof-context accounts with zero
instruction offsets. A third generates and locally verifies SDK proof data,
places its context bytes into in-memory proof-context accounts, and calls
Token-2022's `verify_transfer_proof` helper to confirm it extracts the exact
auditor ciphertext pair and rejects a mutated proof-type tag. The test does not
execute the proof program. A fourth directly invokes Token-2022's
`Processor::process` on a confidential-transfer instruction using in-memory
token accounts and synthetic proof-context accounts derived from locally
verified SDK proof data. The fixture seeds the source account's starting
encrypted balance; changing one byte in either the low or high auditor
ciphertext is rejected before either account changes, while the exact
proof-context pair is accepted and the expected source and destination
ciphertext state is written. It then processes `ApplyPendingBalance` and checks
that the destination's available ciphertext equals full-value encryption with
the combined opening, pending ciphertexts are cleared, and its public token
amount remains zero.

These are not ProgramTest: they do not validate real runtime sysvar loading,
system-account creation, proof-program execution, an actual CPI, or a live
validator transaction. The direct transfer does exercise Token-2022's
processor path, but its accounts and proof contexts are synthetic and its
starting source balance is seeded rather than funded through a deposit.
All ElGamal keys in these fixtures come from known test scalars; nothing here
models or validates DKG.
Treat this as partial processor, context-extraction, and instruction-builder
evidence only.

A host reference predicate recomputes the ElGamal Pedersen commitment and
decryption handle from a public key, amount, and opening. Tests confirm the
SDK-combined low/high ciphertext satisfies that relation and reject mutated
amounts and openings. This is a transparent witness check only, not a ZK proof;
it does not prove an on-chain Token-2022 CPI accepts the context or link a bid
record to a later claim.

The direct-byte predicate now lives in a shared `no_std` relation crate that is
also used by a pinned SP1 v5 guest. Root tests feed it real SDK-serialized
auditor-key and low/high ciphertext bytes, alongside mutations to amount,
opening, key, ciphertext order, claim secret, and bidder. The guest additionally
checks a SHA-256 commitment schema that is explicitly test-only, then commits a
384-byte public statement; private amount/openings/secrets are not in that
statement. The SP1 guest compiles, and a local SP1 core-executor run accepts
the valid fixture, commits the expected 384 public bytes, and rejects a
mutated amount. That run reports 16,789,467 guest instructions; it is not a
generated proof or an on-chain verification result. The future verifier must
compare every public value to the accepted Token-2022 transfer and
proof-context state.
The guest is built with `cargo-prove`/`sp1-zkvm` 5.0.0, while this local
interpreter run uses `sp1-core-executor` 5.2.4; it does not establish
compatibility with the selected Solana verifier, and the instruction count is
not a Solana compute-unit measurement.

The masked-inversion test is a centrally simulated arithmetic transcript, not
an MPC security test or DKG. The DLEQ test uses fixed nonces and does not
implement a production proof encoding, verifier, or nonce generator. The
harness does not implement a client-generated proof linking funded ciphertexts
to private claim notes, Token-2022 CPI, confidential-vault custody, Anchor, or
DBC settlement. Passing tests do not prove those blockers are solved.

The host-side dependency versions are pinned in `Cargo.toml` and `Cargo.lock`;
the isolated ProgramTest and processor-check dependencies have their own
manifests and lockfiles.
Token-2022 9.x uses Solana 2.x program types, so the host processor harness is
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

Verification status as of 2026-09-27: the default host-side suite passes 7/7
tests, `protocol-spike` passes 19/19, and the Token-2022 processor/context/
builder harness passes 4/4. The SP1 v5 guest compiles and passes the local
core-executor test (valid fixture accepted; mutated amount rejected).
Formatting checks pass for the root and SP1 workspace; Clippy passes for the
root, `protocol-spike`, and `token-2022-processor-test` crates.
ProgramTest builds were attempted in the root package before isolation,
serially with debug info disabled and as a metadata-only check, but the
operating system killed `rustc` while compiling `libsecp256k1` before the test
ran. ProgramTest runtime initialization therefore remains unverified.

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
go/no-go criteria before DBC settlement work. See
`SOLANA_ZK_LINKAGE_REVIEW.md` for the separate proof-system and Token-2022
linkage scan.