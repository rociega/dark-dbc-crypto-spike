# Aggregate-Decryption Design

**Status: 3-of-3 selected for implementation. This protocol is not reviewed or
approved for accepting funds or settling launches.**

See [AGGREGATE_DECRYPTION_REVIEW_BRIEF.md](AGGREGATE_DECRYPTION_REVIEW_BRIEF.md)
for the independent-review questions and acceptance criteria.

This note records the selected direction for deriving the public bid total
without giving one prover or trustee every bid opening. It does not authorize enabling
`FundBid` or `Settle`; the compile-time aggregate-proof gate must remain false.

## Findings from the pinned implementation

- The on-chain crate pins `spl-token-2022` 8.0.1 and
  `solana-zk-sdk` 2.2.20. Its ciphertext arithmetic dependency is
  `spl-token-confidential-transfer-ciphertext-arithmetic` 0.3.0.
- Token-2022 represents an ElGamal ciphertext as a 64-byte Pod value containing
  a compressed Pedersen commitment and a compressed decryption handle. A
  confidential transfer passes separate auditor ciphertexts for the low and
  high amount components.
- Token-2022 combines the components as `low + 2^16 * high`. The prototype's
  research relation limits each bid to `2^32 - 1`, so each bid's high component
  is at most `2^16 - 1`. With at most eight bids, each component sum is at most
  `8 * (2^16 - 1) = 524,280`; the reconstructed total is at most
  `8 * (2^32 - 1)`. These bounds still require explicit overflow and unique
  decoding checks in any implementation.
- The pinned ciphertext-arithmetic crate provides homomorphic ElGamal
  addition, and Token-2022 uses it for confidential balance updates.
- The prototype's funding relation binds each hidden amount to both auditor
  ciphertexts. `FundBid` supplies those same ciphertexts to the Token-2022 CPI,
  and appends the bid commitment and transfer-context hash only after the CPI
  succeeds.
- Pool state stores bid commitments, transfer-context hashes, and running
  low/high aggregate auditor ciphertexts. It does not retain each individual
  ciphertext. Finalization blocks later funding and validates the aggregates,
  but does not yet bind a trustee roster, key epoch, or decryption transcript.
- The host-only masked-inversion and Feldman code is still a research model, not
  a distributed key ceremony. The no_std relation now verifies ordered 3-of-3
  inverse-key and aggregate-handle transforms with DLEQ proofs; it does not
  provide trustee enrollment, key custody, authenticated transport, or safe
  production nonce generation. The pinned SDK provides full-secret decryption
  but no threshold-decryption API.

## Selected direction: accumulate ciphertexts on-chain, decrypt only the final sums

The selected design uses ElGamal's additive property on the two auditor components.
For each accepted transfer, the program would update running sums
`C_low = Σ C_low_i` and `C_high = Σ C_high_i`, using the exact ciphertext bytes
passed to the successful Token-2022 CPI. It would do so atomically with the
accepted-bid state update. It must never request or publish a decryption share
for an individual bid.

### 1. Establish the auditor key

The selected model has three independent trustees, each holding one nonzero
scalar factor `s_i`. Each publishes its verification point `V_i = s_i * G`. From
the Token-2022 Pedersen generator `P_0 = H`, trustee `i` computes
`P_i = s_i^-1 * P_(i-1)` and proves
`log_G(V_i) = log_(P_i)(P_(i-1))`. The final auditor key is
`P_3 = H / (s_1 * s_2 * s_3)`, matching the pinned SDK's key mapping.

The proof relation verifies all three transforms in a fixed registered order.
This is a multiplicative 3-of-3 design, not a Shamir DKG: all three trustees
must participate, and any missing trustee blocks decryption. In this prototype,
each trustee ID is the corresponding Solana operator Pubkey. All three operators
must sign the registration transaction and every settlement transaction, whose
proof is bound to the specific pool, auction, epoch, and finalized aggregate.
This is transaction-level authorization, not proof that a signer generated,
exclusively holds, or safely stores its factor. A production identity and key
ceremony, factor custody/recovery, epoch-change policy, and abort handling still
need design and independent review.

### Trustee authorization and aggregate-release policy

The prototype's account contract is fixed: `ConfigureTrustees` receives the
pool, authority, then the three trustee-operator signer accounts in registry
order; `Settle` appends those same three signers after its existing 19 accounts.
The key-setup proof binds the ordered operator Pubkeys and verification shares,
and all three signers authorize the registration transaction. The aggregate
proof binds the pool, auction, key epoch, and finalized bid set, preventing
replay into another pool's statement; all three signers must also authorize the
pool-specific settlement transaction.

This does not prevent trustees from colluding outside the program or decrypting
individual ciphertexts. It also does not prevent differencing across separate
settlements. Until an audited global release ledger or an authenticated
disjoint-cohort mechanism exists, the operating policy is to authorize no more
than one aggregate release for a given funding mint and ordered trustee
verification-share set. Any additional release must be refused when participant
overlap cannot be ruled out. The program does not enforce this cross-pool rule;
the aggregate-proof gate therefore stays false until the enforcement mechanism
and operational controls are implemented and validated.

### 2. Record each accepted transfer

After the CPI and pending-balance application succeed, atomically:

1. Add that transfer's low and high auditor ciphertexts to the running sums.
2. Append the bid commitment and accepted-transfer context hash.
3. Update an authenticated context root over the accepted entries, binding
   each bid commitment to its context hash.

Do not update the accumulator before CPI success. Solana transaction atomicity
must ensure that a later state-write failure also rolls back the CPI.

### 3. Freeze one exact aggregate

Funding finalization must freeze the funded-bid count, claim-membership root,
accepted-transfer context root, both aggregate ciphertexts, auditor key, and
key-setup transcript/epoch identifier. A domain-separated digest over those fields,
the program ID, pool and auction IDs, mint, and protocol version becomes the
only authorized decryption request for that pool.

No subset, per-bid, or post-finalization ciphertext may be submitted for
decryption. The trustee software must refuse requests that do not match the
finalized on-chain state.

### 4. Produce verifiable threshold shares for the two sums

For each component, start at the frozen aggregate handle `D_0`. Trustee `i`
computes `D_i = s_i * D_(i-1)` and supplies a publicly verifiable
equality-of-discrete-logs proof tying that transform to `V_i`. The proof
challenge includes the full finalized aggregate digest, trustee index, key
epoch, and component label. All three ordered proofs are required; there is no
Lagrange reconstruction.

After the third transform, `D_3` is the aggregate opening point because
`D_3 = (s_1 * s_2 * s_3) * r * P_3 = r * H`. The verifier checks that each
aggregate commitment minus its final opening point equals the bounded
`low_total * G` or `high_total * G`, and applies unique-decoding and overflow
checks. Only then may the program set the public total to
`low_total + (high_total << 16)`.

The on-chain program must reject duplicate or unauthorized trustee
contributions, invalid proofs, transforms for another pool or key epoch, replayed
transcripts, and any attempt to change the finalized state. The public total
must be derived from these verified shares, never supplied by the initializer.

## Alternatives and decision

| Approach | Assessment |
|---|---|
| One SP1 prover receives all bid openings | **Reject.** The prover learns individual amounts and claim secrets. |
| Trustees decrypt every bid, then sum | **Reject.** It publishes or exposes individual amounts to the decryption quorum. |
| Threshold-decrypt only an on-chain accumulated ciphertext | **Selected direction, not approved for deployment.** One or two factors cannot complete decryption; all three trustees can collude, and only the intended total should be declassified, subject to the assumptions below. |
| General multi-party ZK proving over all openings | **Not selected.** It may support stronger privacy, but requires a concrete malicious-secure distributed prover, transcript rules, and independent review; no such implementation is present here. |

## Assumptions and unresolved privacy limits

- The 3-of-3 design prevents any one or two trustees from completing
  decryption, but all three can collude and decrypt individual ciphertexts if
  they ignore the protocol. Requiring all three also means one unavailable
  trustee blocks settlement.
- The public total itself can reveal a bid when only one bid is accepted, and
  overlapping or selectively chosen aggregates can leak amounts by
  differencing. The current state permits finalization with one to eight bids.
  A minimum-participation and aggregate-release policy must be selected and
  enforced; this protocol alone does not provide anonymity.
- Redemption amounts, destinations, transaction senders, and timing may provide
  linkage even though claim-registration and redemption nullifiers use separate
  domains. Relaying, batching, and metadata policy are separate requirements.
- The on-chain accumulator retains only the aggregate low/high ciphertexts, not
  individual accepted ciphertexts. Any future state or `FundBid` change must
  preserve the post-CPI update ordering and atomicity.
- The proof relation uses test-domain commitments and synthetic fixtures. A
  production funding prover must bind a real accepted Token-2022 transfer,
  exact mint/vault/key, amount range, and both auditor ciphertexts.
- The high component is described by Token-2022 as 48 bits; this prototype's
  own `u32` bid bound narrows it. The selected decoder, overflow behavior,
  curve arithmetic, and runtime compute budget must be tested against the
  exact pinned dependency and deployed Token-2022 program.
- Operator-Pubkey signatures are required at trustee registration and
  settlement, but production identity verification, factor custody, secure proof
  nonces, authenticated trustee transport, transcript persistence,
  malicious-trustee behavior, liveness, and abort recovery are still absent.

## Required validation before implementation can be enabled

1. Independent cryptographic review of the 3-of-3 multiplicative key setup,
   exact `H/s` key mapping, DLEQ proofs, transcript binding, nonce handling,
   and threat model.
2. Property tests for homomorphic addition at limb boundaries and maximum
   totals; reject overflow, malformed points, omitted entries, duplicate
   entries, and inconsistent low/high totals.
3. Adversarial protocol tests for missing, reordered, or malicious trustees,
   invalid/duplicate shares, trustee aborts, replay across pools/epochs, and
   attempts to request subset or individual-bid decryptions.
4. Solana runtime tests proving that failed CPIs cannot alter the aggregate,
   finalization freezes every transcript field, and the verified total is the
   exact amount withdrawn.
5. Independent audit and exact DBC deployment/build compatibility validation.
   The current Devnet fingerprint does not identify the deployed source.

Until all of these gates pass, keep `AGGREGATE_DECRYPTION_PROOF_READY` false.
This note records a selected design direction, not a security review or
deployment approval.

## Source references

- `onchain/Cargo.toml` and `onchain/Cargo.lock` — pinned Solana and Token-2022
  dependencies.
- `onchain/src/processor.rs` — fail-closed handlers, funding CPI, and state
  update ordering.
- `onchain/src/state.rs` — accepted commitments, context hashes, root, and
  finalization state.
- `proof/relation/src/lib.rs` — synthetic funding relation, ciphertext layout,
  amount bounds, and commitment tree.
- `proof/relation/src/threshold.rs` — 3-of-3 transform and DLEQ-verification
  primitives; not a production trustee service.
- Pinned upstream source files:
  `spl-token-2022 8.0.1/src/extension/confidential_transfer/` and
  `spl-token-confidential-transfer-ciphertext-arithmetic 0.3.0/src/lib.rs`.