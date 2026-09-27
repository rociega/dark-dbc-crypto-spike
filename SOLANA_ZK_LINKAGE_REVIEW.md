# Solana ZK proof and Token-2022 linkage review

## Decision

A targeted public-GitHub scan found examples of Groth16 and SP1 proof
verification on Solana, but no drop-in, independently verified implementation
of the required relation: one private bid amount must open the auction
commitment and also be the amount encrypted in the exact Token-2022 auditor
ciphertext pair accepted for that transfer. No settlement or claim code should
start on the basis of these examples alone.

This was a bounded repository/readme/test-document scan on 2026-09-26, not an
exhaustive library or security audit.

## Potential funding-boundary simplification

The Token-2022 ElGamal ciphertext already contains a hiding Pedersen
commitment. In SDK 7.0.1 its commitment component is `C = a*G + r*H`, and its
decryption handle is `D = r*PK`. The low/high ciphertext combination helper
combines both ciphertext components and their Pedersen openings with the same
16-bit shift. A new [host test](src/lib.rs) confirms that the combined pair
equals a full-amount ciphertext made with the combined opening. This is SDK
algebra evidence only; it does not prove a live transfer or a ZK link.

There may be a simpler funding boundary than a second, independent
amount-commitment hash:

1. Let the bidder pre-register the auction/bid identity, fixed bond, and a
   claim-secret hash. Do not put the amount in public instruction data.
2. Make `fund_bid` CPI to Token-2022's confidential `Transfer`, passing the
   low/high auditor ciphertext pair and proof-context state accounts.
3. Token-2022's transfer processor checks that the supplied auditor pair
   equals the auditor ciphertext pair extracted from the verified transfer
   proof context. Its proof-extraction API supports proof-context state
   accounts when the instruction offset is zero.
4. Only after the CPI succeeds, store those exact ciphertext bytes in the
   funded-bid record/Merkle leaf. The pair itself is then the amount
   commitment; auction ID, bidder, bond, and claim-secret hash remain separate
   fields in the domain-separated record.

The lightweight harness now covers instruction construction, host-side context
extraction, and a direct Token-2022 processor transfer. One test confirms
`inner_transfer` carries the exact auditor ciphertext bytes, all three context
accounts, and zero offsets. Another locally verifies SDK proof data, places its
contexts into synthetic in-memory accounts, calls `verify_transfer_proof`, and
checks exact auditor-ciphertext extraction plus rejection of a mutated
proof-type tag.

A fourth test invokes `Processor::process` with a confidential `Transfer`
instruction and synthetic in-memory proof-context accounts derived from
locally verified proof fixtures. It manually seeds the source account's
starting available-balance ciphertext, confirms one-byte changes to either the
low or high auditor ciphertext are rejected before either account changes,
then confirms the exact pair is accepted and the expected source ciphertext and
destination pending balances are written. It then processes
`ApplyPendingBalance` and confirms the destination available ciphertext equals
full-amount encryption with the combined opening, the pending ciphertexts are
cleared, and the public token amount stays zero. This exercises Token-2022's
transfer and pending-balance processor paths, but not the proof program or a
CPI: the context accounts are synthetic, the pre-transfer balance is seeded,
and neither ProgramTest nor the native Solana runtime runs.
See the [harness tests](token-2022-processor-test/src/lib.rs).

This could remove a separate funding-time proof that equates a Poseidon amount
commitment with the Token-2022 ciphertext: the auction program would store the
same ciphertext pair it just asked Token-2022 to accept. It changes the
commitment schema and timing; it is not a drop-in implementation of the
current "one commitment binds every field" design. It also does not hide the
public link between the bidder's bid record and its ciphertext, nor does it
create a link from that record to a later claim note.

The claim proof still has to show that a hidden amount/opening is consistent
with a ciphertext pair inside the funded-bid root, that the note value is
`floor(a_i * Y / Q)`, and that the nullifier is tied to the precommitted secret.
It must hide the source leaf. The claim proof system, threshold DKG, and vault
custody remain separate blockers. The candidate `fund_bid` CPI has not been
executed in ProgramTest or through a caller program; the direct host processor
test does not establish validator-runtime or CPI behavior.

The protocol spike also has a host-only fixed-depth-three Merkle-path helper
and eight-slot nullifier registration/spend model. It tests path construction,
incremental root updates, registered leaf count, atomic host-side
note/nullifier registration, unique nullifiers, and single-spend state
transitions.
The test-only SHA-256 pair hash is not a selected circuit hash; the helper
publishes the leaf index/path and does not prove note ownership or hide the
funded-bid source.

An alternative-runtime check did not remove the caller-CPI gap. LiteSVM's
program-loading flow expects a compiled SBF program artifact, and this workspace
has neither the SBF builder nor program ELF files. Mollusk is another candidate
for a later SBF-based test, not a replacement for the host processor test.
The installed Rust 1.88 toolchain has no `bpfel-unknown-none` target library,
and no `cargo-build-sbf` command is installed. The available build-helper crate
is from the newer 4.x toolchain line; its compatibility with the pinned
Token-2022 9.0.0 / Solana 2.3 stack has not been established.

The ProgramTest dependency tree is not a small feature toggle: its 2.3.13
manifest directly depends on accounts-db, banks client/server, runtime, and
SVM crates, and the secp256k1 precompile is part of the runtime dependency
graph. There is no ProgramTest feature that removes this stack. Given these
constraints, the most direct next runtime gate remains the isolated ProgramTest
on a larger-memory runner, or a separately provisioned compatible SBF toolchain
and prebuilt program artifacts for Mollusk/LiteSVM.

Sources:

- [ElGamal ciphertext representation, SDK 7.0.1](https://docs.rs/solana-zk-sdk/7.0.1/src/solana_zk_sdk/encryption/elgamal.rs.html)
- [Pedersen commitment representation, SDK 7.0.1](https://docs.rs/solana-zk-sdk/7.0.1/src/solana_zk_sdk/encryption/pedersen.rs.html)
- [Low/high ciphertext and opening combination, proof-generation 0.6.1](https://docs.rs/spl-token-confidential-transfer-proof-generation/0.6.1/src/spl_token_confidential_transfer_proof_generation/lib.rs.html)
- [Token-2022 confidential-transfer processor, 9.0.0](https://docs.rs/spl-token-2022/9.0.0/src/spl_token_2022/extension/confidential_transfer/processor.rs.html)
- [Proof-context account extraction, proof-extraction 0.5.1](https://docs.rs/spl-token-confidential-transfer-proof-extraction/0.5.1/src/spl_token_confidential_transfer_proof_extraction/instruction.rs.html)
- [LiteSVM program-loading API](https://docs.rs/litesvm/0.6.1/litesvm/)
- [Mollusk SVM crate](https://docs.rs/mollusk-svm/0.1.0/mollusk_svm/)

## Required relation

For each of at most eight accepted bids, the protocol must establish that:

- the stored low/high ciphertext pair is the exact auditor pair accepted by
  Token-2022 for that mint and vault transfer;
- a bounded amount `a_i` is encrypted in that pair;
- the funded record is bound to the auction/bid identity and precommitted
  claim-secret hash; and
- the output note value is `floor(a_i * Y / Q)` and its nullifier is bound to
  that secret.

With a separate amount commitment, a client proof must establish equality
between that commitment and the accepted ciphertext. With the CPI alternative
above, the successful Token-2022 CPI can bind the stored ciphertext to the
accepted transfer, but a later client claim proof must still bind its hidden
amount to that ciphertext and establish `v_i = floor(a_i * Y / Q)` without
revealing which funded-bid record or note leaf supplied the claim. The
participation record may identify the bidder; the required privacy property is
that it not be publicly linked to the later claim. Verifying a Token-2022
transfer proof and an unrelated claim proof is not enough. See the fixed-eight
proof contract in `DARK_DBC_REDESIGN.md`.

## Candidates inspected

- [Paraloom Core](https://github.com/paraloom-labs/paraloom-core) describes a
  shielded Solana pool using Groth16 over BN254, verified through Solana's
  `alt_bn128` support. Its README does not establish a circuit for Token-2022
  auditor ciphertexts or the auction commitment-to-transfer relation.
- [ZK Spot Shield](https://github.com/pprogrammingg/zk-spot-shield) describes
  an SP1/Groth16 shielded spot-settlement flow with Merkle membership and
  nullifiers. Its [test matrix](https://github.com/pprogrammingg/zk-spot-shield/blob/main/tests.md)
  says the program tests do not yet test proof verification, CI does not run
  the guest zkVM, and tracked proof bytes are fixtures rather than re-proved
  artifacts. Its README and test matrix therefore do not establish a verified
  on-chain proof path for this project.
- [groth16-solana](https://github.com/occludeprotocol/groth16-solana) describes
  BLS12-381 Groth16 proof encoding and Anchor integration. The inspected README
  does not document the required Token-2022 relation, a measured Solana
  verifier cost for this statement, or independent security review.
- Targeted repository searches for Ristretto/ElGamal proofs on Solana returned
  no direct candidate. Repository search is incomplete, so this is not proof
  that no such work exists.

These projects may be useful as references for Merkle/nullifier designs or
generic proof plumbing. None establishes that the Token-2022 transfer
ciphertext can be linked to the auction commitment under a practical,
reviewed Solana verifier.

## Compatibility risk

The Token-2022 ElGamal key and ciphertext types in the current SDK use the
Ristretto/Curve25519 group. The most concrete Solana pairing-verifier examples
found here use BN254. A BN254 circuit cannot treat Ristretto operations as
native-field operations: the circuit must explicitly implement and cost the
cross-field/group relation, or use a proof architecture that proves the
Ristretto computation off-chain and verifies a succinct proof on-chain. No
inspected candidate supplied this exact bridge or its compute measurements.

An SP1 v5 guest prototype now compiles with `sp1-zkvm`, `sp1-build`, and the
installed `cargo-prove` CLI pinned to 5.0.0, plus `curve25519-dalek` 4.1.3.
The local runner uses the SP1 core executor, core machine, and `sp1-stark`
5.2.4 directly, without the proof-orchestration SDK. Compatibility of this
guest/executor pair with a specific Solana verifier is not established. The
shared `no_std` relation crate checks serialized Ristretto key/ciphertexts,
the low/high amount split, and a test-only SHA-256 bid-commitment schema. The
root host test runs that same relation against bytes produced by Solana's
ElGamal SDK and checks mutations. A local run through the SP1 core executor
accepts the valid fixture, commits the expected 384 bytes, and rejects a
mutated amount, reporting 16,789,467 guest instructions. This is interpreter
execution only: no proof has been generated, and compatibility with the pinned
Solana verifier remains unconfirmed.

This is still a feasibility experiment, not a validated design. A complete
path must bind the exact accepted Token-2022 proof-context state, compare all
public inputs against on-chain accounts, fit Solana transaction/compute limits,
and receive independent cryptographic review. It does not solve the separate
`H / s` threshold-DKG or vault-custody blockers.

## SP1 verifier-version gate

A targeted follow-up of the current SP1-on-Solana path found a concrete
version constraint. SP1's current documentation describes a RISC-V zkVM that
can prove Rust programs and identifies Hypercube as the SP1 v6 proof-system
upgrade. The `succinctlabs/sp1-solana` verifier instead exposes embedded
Groth16 verification keys through SP1 v5.0.0; its test loads a recorded
Fibonacci proof and verifies it with the v5 key. The published `sp1-solana`
crate is still 0.1.0, and the verifier repository explicitly says it is
unaudited. Its README gives a 260-byte Groth16 proof example and notes Solana's
1,232-byte transaction limit, but does not supply a measurement for this
project's proof statement or a reproducible compute-unit benchmark.

Therefore the first compatibility spike should pin SP1 v5 with the matching
`sp1-solana` verifier, or else provide and validate a verifier key/path for the
chosen SP1 v6 proof. Do not treat `sp1-solana` 0.1.0 as v6-compatible without a
fresh proof generated by the exact guest, successful verification in the
pinned Solana runtime, and mutation tests. SP1's Rust guest model makes
`curve25519-dalek` a plausible experiment for checking the Ristretto ciphertext
relation, not a proven guest dependency or a cost estimate.

The nearby `zk-spot-shield` reference does not close this gap: its program
depends on `sp1-solana` 0.1.0 while its host notes SP1 6.1, but its test matrix
explicitly says program tests do not yet exercise proof verification and its
tracked Groth16 bytes are not re-proved in CI. It is useful as interface
scaffolding only, not evidence that the v6 proof verifies with the v5-key
library or that the Token-2022 relation is practical.

Sources:

- [SP1 introduction and v6 proof-system note](https://docs.succinct.xyz/docs/sp1/introduction)
- [`sp1-solana` verifier source and embedded SP1 version keys](https://github.com/succinctlabs/sp1-solana/blob/master/verifier/src/lib.rs)
- [`sp1-solana` example, transaction limit, proof size, and audit disclaimer](https://github.com/succinctlabs/sp1-solana)
- [`sp1-solana` 0.1.0 crate metadata](https://crates.io/crates/sp1-solana)
- [`zk-spot-shield` test matrix](https://github.com/pprogrammingg/zk-spot-shield/blob/main/tests.md)
- [`zk-spot-shield` program dependencies](https://github.com/pprogrammingg/zk-spot-shield/blob/main/program/Cargo.toml)

## Minimum next experiment

Before settlement code:

1. Pin a proof/verifier version pair and freeze the exact public inputs from a
   real Token-2022 confidential-transfer proof context and auditor ciphertext.
2. Implement one bidder-generated guest proof tying that pair and the
   commitment to the same bounded amount, then verify it in a pinned Solana
   test runtime.
3. Mutate the amount, commitment, ciphertext, transfer context, mint, vault,
   auction domain, and claimant secret; every mutation must fail.
4. Measure guest cycles, proof generation time, proof bytes, verifier compute
   units, account count, and transaction size at one and eight bids.
5. Keep the protocol blocked unless the relation is reviewed and the separate
   threshold-DKG and custody gates also pass.
