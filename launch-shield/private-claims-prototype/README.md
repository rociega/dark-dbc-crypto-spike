# Private Claims Prototype

**Status: research-only, unaudited, and not deployable.**

This research track remains isolated from the active public-reveal MVP. Its
host-side tests cover two non-production models: centralized masked inversion
from simulated Shamir shares, and sequential 3-of-3 multiplicative trustee
factors. They do not implement a distributed protocol: all factors and
intermediate values are held in one test process.

The tests check that a centrally simulated masked-inversion calculation agrees
with the Solana ElGamal SDK, that the resulting key can be encoded as the SDK's
Pod type, and that the original secret shares still reconstruct a test
decryption. A host integration test also applies the relation's ordered 3-of-3
DLEQ transforms to SDK-generated ciphertexts. These tests use fixed factors and
nonces; they are not trustee software or production key handling.

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

This remains **research-only, unaudited, and not deployable**. The SP1 guest
contains trustee-key setup and aggregate-decryption relations, and the on-chain
program has a proof-backed `Settle` path. These are not a production key
ceremony or distributed MPC implementation: fixtures use synthetic factors,
nonces, trustee IDs, and account values. There is no production trustee
service, key-management API, or funding-proof client.
The prototype now requires each trustee ID to be a Solana operator Pubkey, with
all three operators signing both trustee registration and settlement. This
proves transaction authorization by those Pubkeys; it does not prove who
generated or custodies the corresponding secret factors. The accepted-bid root
is derived from successful confidential-transfer CPIs and is frozen before
settlement. See the project-level security context in `../../threat_model.md`.

The on-chain code contains the Token-2022 pending-balance and Meteora DBC
`swap2` settlement path, including output-vault delta accounting. The
aggregate-proof gate is deliberately fail-closed: `Initialize`, `FundBid`, and
`Settle` return an error until a reviewed proof binds the public aggregate to
every accepted private bid. In particular, `Initialize` stops before creating
a pool or changing Token-2022 vault credit settings. No funding or swap is
currently possible through this prototype.

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

The pool's total bid amount starts at zero. The `Settle` implementation derives
its candidate total from the proof's public values, reconstructs the aggregate
statement from the finalized accepted-bid state, and verifies the proof before
using that amount. The handler is still blocked by the fail-closed gate above,
so this proof-backed path has not run in a Solana runtime. The local relations
do not authenticate trustee identities, provide production key custody, or
handle malicious trustees. Do not use them with funds, real keys, or a deployed
program.

A single-prover SP1 proof over all bid openings is not a safe shortcut: its
prover would learn each amount and claim secret. Aggregate verification must
preserve that information from any one operator.

The selected 3-of-3 direction and its unresolved assumptions are documented in
[AGGREGATE_DECRYPTION_DESIGN.md](AGGREGATE_DECRYPTION_DESIGN.md). It uses
homomorphic accumulation of accepted auditor ciphertexts and decryption of only
the frozen aggregate. The guest relation and proof-backed `Settle` code are
implemented, but the on-chain gate remains disabled and neither runtime
compatibility nor production trustee security has been established. The
independent-review scope and acceptance criteria are in
[AGGREGATE_DECRYPTION_REVIEW_BRIEF.md](AGGREGATE_DECRYPTION_REVIEW_BRIEF.md).

## On-chain claims prototype

The separate `onchain` crate has seven instruction encodings: initialize a pool,
configure trustees, accept a funded bid, finalize funding, settle through DBC,
register a claim proof, and redeem a note. Pool initialization binds one
Token-2022 funding mint and confidential vault, including the mint's auditor key
and the vault's ElGamal key. `ConfigureTrustees` requires the authority and
three ordered trustee-operator signers; each signer's Pubkey must equal the
corresponding trustee ID bound by the key-setup proof. The state format is now
version 6 because `trustee_ids` are operator Pubkeys; version-5 pool data is
rejected rather than reinterpreted. The `FundBid` handler
contains checks for the statement's bidder, mint, vault, auditor key,
ciphertexts, and transfer-context hash; its CPI path verifies an SP1 funding
proof, invokes Token-2022 v8.0.1, applies the pending credit, and disables
further confidential credits. Initialization also disables public credits. The
fixed-eight funded-bid root is designed to contain only commitments whose CPIs
succeeded. `FinalizeFunding` freezes that root. The `Initialize`, `FundBid`,
and `Settle` handlers currently stop at fail-closed guards, so pool creation,
transfer, and settlement paths cannot be used yet. The initialization guard
runs before pool creation or Token-2022 credit-setting CPIs.

The `Settle` code reconstructs the aggregate statement from the frozen bid set,
verifies the SP1 proof, withdraws the proven bid total, and calls DBC `swap2`
with the Token-2022 funding mint as quote and the classic SPL output mint as
base. The caller must provide an existing DBC pool and Token-2022 withdrawal
proof contexts. The 19 base accounts are followed by the three matching
trustee-operator signers, a global aggregate-release registry PDA, and the
system program (24 accounts total). The registry is keyed by funding mint and
an order-independent hash of the trustee-operator roster. It permits one
aggregate release for that mint and roster across pools and key epochs, records
the pool and finalized aggregate digest, and is created atomically with
settlement. This intentionally blocks unrelated pools that reuse the same mint
and roster. The DBC CPI and withdrawal are atomic; the instruction records the
actual output token balance delta, and claim registration stays blocked until
settlement succeeds. The compile-time aggregate-proof gate is currently false,
so this path is disabled and has not been runtime-tested.
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

The on-chain suite covers state, parsing, verifier, and DBC instruction
construction with 25 unit tests. One Solana ProgramTest regression also passes:
it confirms gated `Initialize`, `FundBid`, and `Settle` return `Custom(3)` without
changing a writable sentinel account. This exercises only the early fail-closed
guards; it does not reach a CPI or validate rollback behavior.

An earlier SBF build with Agave 4.3.0 and platform-tools 1.57 produced:

```sh
PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH" \
  env -u LD_AUDIT cargo build-sbf \
    --manifest-path launch-shield/private-claims-prototype/onchain/Cargo.toml \
    --sbf-out-dir /tmp/private-claims-sbf \
    --arch v2 \
    --patch-binaries-for-nix false
```

That pre-pin SBF artifact was 176,560 bytes with SHA-256
`33709456109be3768efd1e0c5865dac49ad8269f5af5a161e2a3278c3b5c1d6d`; it does
not contain the current verifier-key pin and must not be used as a release
artifact.

After the verifier-pin update, Agave `cargo-build-sbf` 4.3.0 with platform-tools
1.57 successfully built the on-chain program for `arch v2` on 2026-10-01. The
artifact was 224,560 bytes with SHA-256
`09dd6b81a728fba43852a270bc22105a5b2dc4ba5056516823e9f612049eaf01`. A later
workspace restart removed both the temporary artifact and the user-local
builder installation, so this hash records a successful build but the binary
must be rebuilt before release. SBF compilation does not validate CPI behavior,
DBC compatibility, or deployment readiness. The gated instructions remain
disabled, and no program was deployed or used to create a pool.

## Host tests

Run with Rust 1.88 or later:

```sh
env -u LD_AUDIT CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --manifest-path launch-shield/private-claims-prototype/Cargo.toml
env -u LD_AUDIT CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked \
  --manifest-path launch-shield/private-claims-prototype/proof/relation/Cargo.toml
env -u LD_AUDIT CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked \
  --manifest-path launch-shield/private-claims-prototype/onchain/Cargo.toml
```

On 2026-10-01, all 21 arithmetic-gate tests, all 10 relation tests, all 25
on-chain unit tests, and the fail-closed ProgramTest passed. The proof guest
passed host `cargo check`, and all five guest modes executed in the SP1 local
executor; mutated funding, claim, redemption, trustee-key setup, and
aggregate-decryption inputs were rejected. The ProgramTest covers only guarded
early exits, not CPI behavior. Local Groth16 proof generation did not complete;
the production trustee/key-ceremony and malicious-trustee caveats above still
apply.

## SP1 guest and local execution

The nested proof workspace is pinned to SP1 6.8.1. This guest was built with the
matching `cargo-prove` v6.8.1 release and its `succinct` Rust 1.96.0-dev
toolchain. On a fresh environment, install the matching release and toolchain
first. Note that
`cargo prove install-toolchain` resets `~/.sp1`; preserve any older SP1
toolchain before running it.

```sh
mkdir -p /tmp/private-claims-guest-elf
cd launch-shield/private-claims-prototype/proof
env -u LD_AUDIT cargo prove build --locked \
  -p private-claims-proof-guest \
    --elf-name private-claims-guest \
  --output-directory /tmp/private-claims-guest-elf

env -u LD_AUDIT \
  CARGO_PROFILE_DEV_DEBUG=0 \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=target \
  PRIVATE_CLAIMS_GUEST_ELF=/tmp/private-claims-guest-elf/private-claims-guest \
  cargo run --locked --manifest-path script/Cargo.toml --features local-executor
```

The runner also provides a `show-vkey` subcommand to calculate the verifier-key
hash without checking the checked-in pin:

```sh
cd launch-shield/private-claims-prototype/proof
env -u LD_AUDIT \
  CARGO_PROFILE_DEV_DEBUG=0 \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=target \
  PRIVATE_CLAIMS_GUEST_ELF=/tmp/private-claims-guest-elf/private-claims-guest \
  cargo run --locked --manifest-path script/Cargo.toml \
    --features local-executor -- show-vkey
```

The built guest ELF had SHA-256
`9c1f5953e0d61c0316a3e29d751c33a54b84008d689e65584235e4e442858fb2`. Its
locally calculated verifier-key hash matched the updated pin in
`guest-vkey-hash.txt`. The full local-executor run passed for funding, claim,
redemption, trustee key setup, and aggregate decryption, including rejection of
mutated inputs. The executor run is not a Groth16 proof-generation or
proof-verification test. No proof artifact was produced under the updated pin:
the default CPU run was lost during a workspace restart, a one-thread run was
killed with exit code 137 after reaching about 6.5 GiB of resident memory, and
a lower-memory run using `SHARD_SIZE=500000`, `TRACE_CHUNK_SLOTS=1`,
`GAS_TRACE_CHUNK_SLOTS=1`, and single-core affinity was lost in another
workspace restart before producing output. At the last check it used about
2.4 GiB of resident memory; the restart cause is unknown. The on-chain proof
paths remain fail-closed; the ProgramTest covers only their guarded early
exits.

## Local claim and redemption proof generation

The runner defines opt-in CPU Groth16 proving paths for synthetic funding,
claim, redemption, aggregate-decryption, and trustee-key-setup fixtures. The
code verifies generated proofs with the SP1 SDK and the on-chain verifier and
writes proof bytes and public values to the selected output directory. The
aggregate-decryption proving run was OOM-killed without artifacts. The
trustee-key-setup run reached 7,350,222,848 bytes of cgroup usage (about 6.84
GiB; 5.91 GiB RSS) and was stopped before another OOM kill; it produced no
proof files. Funding, claim, and redemption proof generation was not attempted.
Their fixtures use
hard-coded deterministic test factors, nonces, and account values. They are not
suitable for launch or real trustee configuration. No production proof-input
client is implemented. All paths require the guest ELF and verifier-key pin to
match.

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

## Private Reserved synthetic proof attempt

The `network-prover` feature passed `cargo check --locked` with Rust 1.96.0.
The preserved guest ELF matched its expected SHA-256, the locally calculated
verifier-key hash matched `guest-vkey-hash.txt`, and the signer-format preflight
passed. A single private Reserved request using the deterministic synthetic
trustee-key-setup fixture was attempted on 2026-10-02.

The runner returned `SP1_FAILURE stage=private_reserved_submit
SP1_ERROR_UNCLASSIFIED` before it returned a request ID. Only the attempt log
was persisted; no request-ID, proof, or public-values file exists. Acceptance
is unknown, not confirmed absent. Do not retry this request automatically or
submit another proof without fresh explicit authorization. No proof was
verified, and the aggregate-proof gate remains fail-closed.

## Required work before this can become deployable

- Implement and independently review a production 3-of-3 key ceremony for
  Token-2022's exact `H/s` mapping, including authenticated trustees, factor
  custody, secure proof nonces, and abort/recovery behavior.
- Replace the test-domain commitments and build a funding-proof client that
  constructs the statement from a real confidential transfer and its context
  accounts.
- Generate and verify local Groth16 proofs under the updated SP1 verifier-key
  pin. The guest build, local-executor fixtures, and pin update are complete,
  but aggregate and trustee-key-setup proving runs remain unverified: the
  aggregate run was OOM-killed, and the trustee run was stopped at about
  6.84 GiB cgroup usage. Neither produced proof artifacts.
- The prototype now binds trustee IDs to signer Pubkeys during registration and
  requires the same three signers for each settlement. This is transaction-level
  authorization only; it does not authenticate real-world identities or prove
  that a signer exclusively controls or safely stores its factor.
- The program now prevents a second aggregate release for the same funding mint
  and trustee-operator roster across pools and key epochs. This is deliberately
  stricter than a disjoint-cohort ledger, and it does not prove disjoint
  participants across different rosters or program deployments. Independently
  review the guard and define an operational policy for those cases before
  enabling the settlement path.
- Confirm the DBC CPI account layout and Token-2022 pool support against the
  exact pinned deployment, and validate settlement in a Solana runtime.
- Test CPI and verifier failures, replay attempts, and settlement boundaries.
- Build for SBF and validate against the exact DBC/Token-2022 runtime before
  considering Devnet. Do not create a public test pool or send an irreversible
  Devnet transaction without presenting the exact action and receiving final
  confirmation.
- Complete independent cryptographic and program audits before deployment.