# Candidate Aggregate-Decryption Design

**Status: analysis only. This is not an implemented, reviewed, or approved protocol.**

This note records a candidate for deriving the public bid total without giving
one prover or trustee every bid opening. It does not authorize enabling
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
- Current pool state stores bid commitments and transfer-context hashes, but
  not the auditor ciphertexts or an aggregate ciphertext. The funded-bid Merkle
  root covers commitments; `FinalizeFunding` freezes that root only. Context
  hashes cannot be used to recover or add the ciphertexts.
- The current `H/s` key derivation and Feldman checks are in-process research
  models, not a DKG or threshold-decryption implementation. The pinned SDK
  provides full-secret decryption but no threshold-decryption API.

## Candidate: accumulate ciphertexts on-chain, decrypt only the final sums

The candidate uses ElGamal's additive property on the two auditor components.
For each accepted transfer, the program would update running sums
`C_low = Σ C_low_i` and `C_high = Σ C_high_i`, using the exact ciphertext bytes
passed to the successful Token-2022 CPI. It would do so atomically with the
accepted-bid state update. It must never request or publish a decryption share
for an individual bid.

### 1. Establish the auditor key

Before accepting funds, use an independently reviewed malicious-secure 2-of-3
DKG and distributed-inversion protocol that produces the exact Token-2022
auditor key required by the pinned SDK. The protocol must bind the public key
to verifiable trustee shares, reject a zero/invalid joint secret, authenticate
transcripts, and define complaints, aborts, participant identities, and
protocol versioning.

The test model's `H/s` mapping is a constraint to preserve, not evidence that a
production DKG or inversion protocol exists. The selected protocol must prove
that its shares implement the SDK's actual encryption/decryption equation.

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
DKG transcript/epoch identifier. A domain-separated digest over those fields,
the program ID, pool and auction IDs, mint, and protocol version becomes the
only authorized decryption request for that pool.

No subset, per-bid, or post-finalization ciphertext may be submitted for
decryption. The trustee software must refuse requests that do not match the
finalized on-chain state.

### 4. Produce verifiable threshold shares for the two sums

Each trustee computes partial decryptions only for the frozen low and high
aggregate handles. For each component, it supplies a publicly verifiable
equality-of-discrete-logs proof tying its partial decryption to its DKG
verification share. The proof challenge must include the full finalized
aggregate digest, trustee index, DKG epoch, and component label.

Two valid shares are combined with the DKG's specified Lagrange coefficients.
The committee reports bounded `low_total` and `high_total`; the verifier checks
that the reconstructed plaintext points equal `low_total * G` and
`high_total * G`, respectively, and checks the component and total bounds.
Only then may the program set the public total to
`low_total + (high_total << 16)`.

The on-chain program must reject duplicate or unauthorized trustee
contributions, invalid proofs, shares for another pool or DKG epoch, replayed
transcripts, and any attempt to change the finalized state. The public total
must be derived from these verified shares, never supplied by the initializer.

## Alternatives and decision

| Approach | Assessment |
|---|---|
| One SP1 prover receives all bid openings | **Reject.** The prover learns individual amounts and claim secrets. |
| Trustees decrypt every bid, then sum | **Reject.** It publishes or exposes individual amounts to the decryption quorum. |
| Threshold-decrypt only an on-chain accumulated ciphertext | **Candidate for independent review.** A single trustee's share is insufficient to recover an amount, and only the intended total is declassified, subject to the assumptions below. |
| General multi-party ZK proving over all openings | **Not selected.** It may support stronger privacy, but requires a concrete malicious-secure distributed prover, transcript rules, and independent review; no such implementation is present here. |

## Assumptions and unresolved privacy limits

- A 2-of-3 threshold protects against one curious or compromised trustee, not
  two colluding trustees. Any threshold quorum can decrypt individual
  ciphertexts if it ignores the protocol. If privacy must survive two trustee
  compromises, this threshold is insufficient.
- The public total itself can reveal a bid when only one bid is accepted, and
  overlapping or selectively chosen aggregates can leak amounts by
  differencing. The current state permits finalization with one to eight bids.
  A minimum-participation and aggregate-release policy must be selected and
  enforced; this protocol alone does not provide anonymity.
- Redemption amounts, destinations, transaction senders, and timing may provide
  linkage even though claim-registration and redemption nullifiers use separate
  domains. Relaying, batching, and metadata policy are separate requirements.
- The accepted-transfer context currently commits to the auditor ciphertexts
  but does not retain those ciphertexts in recoverable form. A hash alone is
  not an accumulator. The state and `FundBid` path need an audited design
  change before the proposed aggregation can be implemented.
- The proof relation uses test-domain commitments and synthetic fixtures. A
  production funding prover must bind a real accepted Token-2022 transfer,
  exact mint/vault/key, amount range, and both auditor ciphertexts.
- The high component is described by Token-2022 as 48 bits; this prototype's
  own `u32` bid bound narrows it. The selected decoder, overflow behavior,
  curve arithmetic, and runtime compute budget must be tested against the
  exact pinned dependency and deployed Token-2022 program.
- DKG share validation, distributed inversion, decryption-share proofs,
  malicious-trustee behavior, liveness, and abort recovery are all absent.

## Required validation before implementation can be enabled

1. Independent cryptographic review of the DKG, exact `H/s` key mapping,
   verifiable partial-decryption proof, transcript binding, and threat model.
2. Property tests for homomorphic addition at limb boundaries and maximum
   totals; reject overflow, malformed points, omitted entries, duplicate
   entries, and inconsistent low/high totals.
3. Adversarial protocol tests for one malicious trustee, invalid/duplicate
   shares, trustee aborts, replay across pools/epochs, and attempts to request
   subset or individual-bid decryptions.
4. Solana runtime tests proving that failed CPIs cannot alter the aggregate,
   finalization freezes every transcript field, and the verified total is the
   exact amount withdrawn.
5. Independent audit and exact DBC deployment/build compatibility validation.
   The current Devnet fingerprint does not identify the deployed source.

Until all of these gates pass, keep `AGGREGATE_DECRYPTION_PROOF_READY` false.
This note is a candidate design, not a security review or deployment approval.

## Source references

- `onchain/Cargo.toml` and `onchain/Cargo.lock` — pinned Solana and Token-2022
  dependencies.
- `onchain/src/processor.rs` — fail-closed handlers, funding CPI, and state
  update ordering.
- `onchain/src/state.rs` — accepted commitments, context hashes, root, and
  finalization state.
- `proof/relation/src/lib.rs` — synthetic funding relation, ciphertext layout,
  amount bounds, and commitment tree.
- Pinned upstream source files:
  `spl-token-2022 8.0.1/src/extension/confidential_transfer/` and
  `spl-token-confidential-transfer-ciphertext-arithmetic 0.3.0/src/lib.rs`.