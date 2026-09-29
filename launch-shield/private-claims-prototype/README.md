# Private Claims Prototype

**Status: research-only, unaudited, and not deployable.**

This research track remains isolated from the active public-reveal MVP. Its
host-side tests check arithmetic needed to derive the Token-2022 ElGamal
public-key point `H/s` from simulated 2-of-3 Shamir shares. They do not
implement a distributed protocol: all shares and intermediate values are held
in one test process.

The tests check that a centrally simulated masked-inversion calculation agrees
with the Solana ElGamal SDK, that the resulting key can be encoded as the SDK's
Pod type, and that the original secret shares still reconstruct a test
decryption. They also cover two invalid arithmetic shortcuts.

The test-only Feldman model checks that shares match the public polynomial
commitments and that a zero aggregate secret is detectable. It is an
in-process simulation, not a network protocol or a complete DKG.

The shared `no_std` funding relation checks a test-domain amount commitment
against the hidden amount and both serialized auditor ciphertexts. An SP1
6.8.1 guest invokes this relation and commits the 384-byte statement as public
values. The runner's fixtures use synthetic keys, ciphertexts, proof-context
accounts, and transfer-context hashes. Its default local-executor mode does not
generate proofs; its opt-in CPU prover can produce Groth16 proofs for those
synthetic fixtures, which are not valid evidence of a real accepted transfer.

The same relation crate now contains a fixed-eight claim-note relation. It
checks membership of a hidden funded-bid commitment in a depth-three SHA-256
tree, derives the floor-pro-rata output allocation using bounded integer
arithmetic, and binds a randomized note commitment to a domain-separated
nullifier. The SP1 guest supports both funding and claim relation modes; claim
public values are 208 bytes. The host tests and local runner use synthetic
fixtures only.

The guest also has a redemption mode. It proves membership of a hidden note in
a depth-three note tree, derives the note's public nullifier from its private
funding commitment and secret, and binds the public redemption amount, output
mint, and destination into the 200-byte statement. The relation itself is
stateless; a separate research-only Solana program records spent nullifiers and
can transfer classic SPL output tokens.

Claim registration and redemption use separate domain-separated nullifiers. The
claim nullifier prevents registering the same funded bid twice; the redemption
nullifier prevents replay at payout. Reusing one public nullifier for both
actions would directly link a claim to its later redemption.

The relation and guest alone do not establish that Token-2022 accepted a
transfer. The prototype's on-chain `FundBid` handler now checks the funding
statement against the configured Token-2022 mint and confidential vault, verifies
the SP1 proof, and passes the proof's auditor ciphertexts and proof-context
accounts to Token-2022's confidential-transfer CPI. It appends the bid
commitment to the funded-bid tree only after the CPI succeeds. The shared
relation crate exposes the canonical proof-context and accepted-transfer context
hash functions used to bind those CPI inputs.

This remains **research-only, unaudited, and not deployable**. It is not a DKG,
MPC implementation, malicious-secure protocol, aggregate-decryption system, or
production key-management API. The accepted-bid root is derived from successful
confidential-transfer CPIs and is frozen before settlement.

The on-chain code contains the Token-2022 pending-balance and Meteora DBC
`swap2` settlement path, including output-vault delta accounting. That path is
deliberately fail-closed: both `FundBid` and `Settle` return an error until a
reviewed proof binds the public aggregate to every accepted private bid. No
funding or swap is currently possible through this prototype.

Source review at Meteora DBC 0.2.1 commit
`f552f20aa3c1c7631427c3827aeea7c58b902813` confirms that `swap2` uses
`TokenInterface` for both token programs and token accounts. Its Token-2022 pool
initializer also accepts the quote-token program through `TokenInterface`.
Host-side tests cover the prototype's `swap2` discriminator/data, account order
and flags, no-referral sentinel, event accounts, Instructions sysvar, and pool
PDA mint ordering. This confirms the source-level interface, not the deployed
Devnet program's source or runtime behavior.
In this source, `swap2` transfers input using its signer `payer` and rejects
quote mints with a nonzero active or scheduled transfer fee. The prototype
passes its confidential-vault authority PDA as that payer and signs the CPI
with the PDA seeds; runtime behavior is still unverified.

A read-only Devnet check on 2026-09-29 still matched the recorded program
fingerprint in `launch-shield/README.md`. Rebuilding the reviewed DBC 0.2.1
commit with Agave 4.3.0/platform-tools 1.57 produced distinct SBF artifacts:

| Build | Bytes | SHA-256 |
|---|---:|---|
| arch v0 | 1,498,608 | `6587ce450a06cca876f58be7444e33d1e5939e444652fa4161f8b6d90fe692f8` |
| arch v1 | 1,499,816 | `dcab965f511e92f41df935ded3232e6a4c8d9d0662269078e071660a9b1c29df` |
| arch v2 | 1,506,544 | `a10f0f93c3a0419a5078446a9c3772d13ddbf0a8ed6b9f11d792e792d083579a` |
| arch v3 | 1,426,928 | `238d2bc89a20a0898b081da722f7de2858d797dd875f60767161c9d55432ff2b` |
| arch v3 with ABI v2 | 1,426,928 | `d39c027799cea00f5f8cf766a5f768834eaf55cce4668604ac83f81ef3813de0` |

None matches the recorded Devnet executable (1,983,568 bytes,
`f5ccbb01e37165d16108bda0259fb3acbfca29305e23098c3b248e50c22979f0`). An arch
v4 build did not compile because platform-tools 1.57 lacks the
`sbpfv4-solana-solana` standard-library target. The deployed source and build
configuration therefore remain unidentified, and runtime CPI compatibility is
still unverified.

The configured total bid amount is still authority-provided at initialization.
Token-2022's withdrawal proof establishes that the vault can cover the
withdrawal, but does not establish that the amount is the full accepted-bid
aggregate. The program therefore still lacks the threshold aggregate-decryption
proof needed to bind that public amount to all accepted transfers. The
research-only relations also do not authenticate DKG participants, validate
protocol transcripts, or handle malicious trustees. Do not use them with funds,
real keys, or a deployed program.

A single-prover SP1 proof over all bid openings is not a safe shortcut: its
prover would learn each amount and claim secret. Aggregate verification must
preserve that information from any one operator.

## On-chain claims prototype

The separate `onchain` crate has six instruction encodings: initialize a pool,
accept a funded bid, finalize funding, settle through DBC, register a claim
proof, and redeem a note. Pool initialization binds one Token-2022 funding mint
and confidential vault, including the mint's auditor key and the vault's
ElGamal key. The `FundBid` handler contains checks for the statement's bidder,
mint, vault, auditor key, ciphertexts, and transfer-context hash; its CPI path
verifies an SP1 funding proof, invokes Token-2022 v8.0.1, applies the pending
credit, and disables further confidential credits. Initialization also disables
public credits. The fixed-eight funded-bid root is designed to contain only
commitments whose CPIs succeeded. `FinalizeFunding` freezes that root. The
`FundBid` and `Settle` handlers currently stop at a fail-closed guard, so these
transfer and settlement paths cannot be used yet.

Once the aggregate proof is implemented, `Settle` is intended to withdraw the
verified bid total and call DBC `swap2` with the Token-2022 funding mint as quote
and the classic SPL output mint as base. The caller must provide an existing DBC
pool and Token-2022 withdrawal proof contexts. The DBC CPI and withdrawal are
atomic; the instruction records the actual output token balance delta, and
claim registration stays blocked until settlement succeeds. Currently, the
configured bid total is not proven to equal the sum of accepted confidential
transfers, which is why funding and settlement are disabled.
Auction IDs are derived as
`SHA256("private-claims:auction-id:test-v1" || program_id || authority ||
nonce)`. The program uses the shared SP1 guest hash in
`guest-vkey-hash.txt`; the local runner checks that it still matches the guest
ELF.

Run its host-side tests with:

```sh
env -u LD_AUDIT CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 cargo test --locked \
    --manifest-path launch-shield/private-claims-prototype/onchain/Cargo.toml
```

These cover state, parsing, verifier, DBC instruction-construction, and the
handler-level fail-closed funding/settlement guards—not Solana runtime/CPI
behavior. All 17 on-chain host tests passed on 2026-09-29. The on-chain crate
successfully built for SBF with Agave 4.3.0 and platform-tools 1.57:

```sh
PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH" \
  env -u LD_AUDIT cargo build-sbf \
    --manifest-path launch-shield/private-claims-prototype/onchain/Cargo.toml \
    --sbf-out-dir /tmp/private-claims-sbf \
    --arch v2 \
    --patch-binaries-for-nix false
```

The resulting SBF artifact's SHA-256 was
`164b3cf69cc4c86157e1e25c5aecb1f500d391815f582e666c790e0feec92025`. It has
not been executed in ProgramTest or deployed/tested on Devnet. A successful
compiler build does not validate runtime correctness, CPI behavior, DBC
compatibility, or deployment readiness; `FundBid` and `Settle` remain
fail-closed.

## Host tests

Run with Rust 1.88 or later:

```sh
cargo test --locked --manifest-path launch-shield/private-claims-prototype/Cargo.toml
```

On 2026-09-29, this workspace suite passed all 20 arithmetic-gate host tests.
The on-chain crate separately passed all 17 host tests. Neither command runs a
Solana runtime/CPI test; the research-only DKG and malicious-trustee caveats
above still apply.

## SP1 guest and local execution

The nested proof workspace is pinned to SP1 6.8.1. On a fresh environment,
install the matching `cargo-prove` release and toolchain first. Note that
`cargo prove install-toolchain` resets `~/.sp1`; preserve any older SP1
toolchain before running it.

```sh
mkdir -p /tmp/private-claims-guest-elf
cd launch-shield/private-claims-prototype/proof
cargo prove build --locked \
  -p private-claims-proof-guest \
    --elf-name private-claims-guest \
  --output-directory /tmp/private-claims-guest-elf

CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR=/tmp/private-claims-proof-target \
PRIVATE_CLAIMS_GUEST_ELF=/tmp/private-claims-guest-elf/private-claims-guest \
  cargo run --locked --manifest-path script/Cargo.toml --features local-executor
```

The local runner checks valid synthetic funding, claim, and redemption fixtures
and rejects mutated amount, ciphertext, claim-path, and redemption-path inputs,
as well as reuse of a claim nullifier as a redemption nullifier. This is VM
execution, not proof generation, on-chain verification, or a Token-2022 CPI
test.

## Local claim and redemption proof generation

The runner has opt-in CPU Groth16 proving paths for synthetic funding, claim,
and redemption fixtures. Each path verifies the generated proof with the SP1
SDK and the same verifier implementation used by the on-chain claims program,
then writes only the proof bytes and public values to the selected output
directory. For example:

```sh
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_INCREMENTAL=0 \
PRIVATE_CLAIMS_GUEST_ELF=/tmp/private-claims-guest-elf/private-claims-guest \
  cargo run --locked \
    --manifest-path launch-shield/private-claims-prototype/proof/script/Cargo.toml \
    --features local-prover -- \
    prove-funding /tmp/private-claims-funding-proof
```

Use `prove-redemption /tmp/private-claims-redemption-proof` for a redemption
proof:

```sh
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_INCREMENTAL=0 \
PRIVATE_CLAIMS_GUEST_ELF=/tmp/private-claims-guest-elf/private-claims-guest \
  cargo run --locked \
    --manifest-path launch-shield/private-claims-prototype/proof/script/Cargo.toml \
    --features local-prover -- \
    prove-redemption /tmp/private-claims-redemption-proof
```

Use `prove-claim /tmp/private-claims-claim-proof` for a claim registration
proof. Outputs are named `funding.proof` and `funding.public-values`,
`redemption.proof` and `redemption.public-values`, or `claim.proof` and
`claim.public-values`.

CPU proving can be resource-intensive. This mode uses synthetic data only; it
does not prove that a Token-2022 transfer was accepted, bind a funded-bid root
to transfers, or perform DBC settlement.

## Required work before this can become deployable

- Select and implement a reviewed malicious-secure 2-of-3 DKG and distributed
  inversion protocol for Token-2022's exact `H/s` mapping.
- Add authenticated transcripts, verifiable shares, complaint/abort handling,
  and production randomness.
- Replace the test-domain commitments and build a funding-proof client that
  constructs the statement from a real confidential transfer and its context
  accounts.
- Implement a reviewed malicious-secure DKG and aggregate-only decryption path;
  use it to set the bid total from accepted transfers instead of trusting the
  initializer.
- Confirm the DBC CPI account layout and Token-2022 pool support against the
  exact pinned deployment, and validate settlement in a Solana runtime.
- Test CPI and verifier failures, replay attempts, and settlement boundaries.
- Build for SBF, then deploy and verify on Devnet only after the protocol and
  settlement prerequisites are implemented.
- Complete independent cryptographic and program audits before deployment.