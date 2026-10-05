# Independent Cryptographic Review Brief

**Status: request for independent review only. This brief does not approve a
protocol or authorize deployment.**

## Review request

Independently assess the selected 3-of-3 multiplicative design in
[AGGREGATE_DECRYPTION_DESIGN.md](AGGREGATE_DECRYPTION_DESIGN.md). Determine
whether it can derive one public total from accepted Token-2022 confidential
transfers without exposing individual bid amounts to fewer than all three
trustees. Approve the complete protocol only if its assumptions are supported;
otherwise issue a no-go and identify required changes. Do not treat the
relation-level primitives as a production implementation.

## Current state and safety boundary

- `AGGREGATE_DECRYPTION_PROOF_READY` remains `false`. `Initialize`, `FundBid`,
  and `Settle` are fail-closed.
- Pool state accumulates low/high auditor ciphertexts after successful CPIs,
  retains the accepted-bid commitments and transfer-context hashes, and stores
  the registered trustee roster, key epoch, and verification shares. It does
  not retain individual ciphertexts or a per-trustee decryption transcript.
- Settlement now consumes a global PDA keyed by funding mint and the
  order-independent trustee-operator roster. It records one release across
  pools and key epochs for that mint and roster. This is a conservative guard,
  not a disjoint-cohort proof or a cross-program global ledger.
- The no_std relation verifies ordered 3-of-3 inverse-key and aggregate-handle
  transforms with DLEQ proofs. It does not provide key ceremony, trustee
  enrollment or custody, authenticated transport, production nonce generation,
  or on-chain transcript consumption.
- Host tests and SBF compilation do not validate the cryptographic protocol or
  Token-2022/DBC runtime behavior.
- No real keys, bid openings, funds, or deployment authority are in scope for
  this review.

Keep the gate closed throughout review and any design iteration.

## Version-sensitive starting facts to verify

The selected design records the following pinned-source facts. Recheck them
against `Cargo.lock` and the exact upstream source before relying on them:

- Token-2022 is pinned to 8.0.1, `solana-zk-sdk` to 2.2.20, and confidential
  transfer ciphertext arithmetic to 0.3.0.
- An auditor ciphertext is a 64-byte value containing a commitment and a
  decryption handle. Transfers supply separate low and high auditor
  ciphertexts, combined as `low + 2^16 * high`.
- The prototype limits each bid to `2^32 - 1` and the pool to eight bids. Under
  those limits, either component sum is at most `8 * (2^16 - 1) = 524,280`,
  and the reconstructed total is at most `8 * (2^32 - 1)`.

The reviewer must independently confirm the representation, key equation,
component semantics, bounds, and unique-decoding argument. Do not treat this
summary as a substitute for checking the pinned implementation.

## Desired security properties

The reviewed design must:

1. Establish the exact auditor ElGamal key required by the pinned Token-2022
   implementation using three independent, nonzero trustee factors.
2. Bind the key and each public verification point to operator Pubkeys, a key
   epoch, and an unambiguous protocol version. Assess whether the prototype's
   registration and per-settlement signer checks provide the intended
   transaction authorization; separately require a production identity and
   factor-custody ceremony.
3. Accumulate only ciphertexts from transfers whose Token-2022 CPI and pending
   balance application succeeded.
4. Allow threshold decryption only for the immutable, finalized aggregate
   authorized by the on-chain accepted set.
5. Make each sequential decryption transform publicly verifiable and bound to the
   finalized aggregate, pool, key epoch, trustee identity, and ciphertext
   component.
6. Derive a unique, bounded integer total and reject malformed points, overflow,
   duplicate or omitted entries, invalid shares, replay, and mismatched low/high
   components.
7. Define a release policy that addresses lone-bid disclosure and differencing
   across overlapping pools or epochs. A minimum participation count alone must
   not be assumed to prevent differencing.
8. Specify malicious-trustee behavior, complaints, aborts, retries, liveness,
   and safe cancellation or refund behavior before funds can be accepted.

## Threat model decisions the review must make explicit

The selected model requires all three factors. One or two trustees cannot
complete decryption, but all three can collude and decrypt individual
ciphertexts if they ignore the intended workflow. One unavailable trustee also
blocks settlement. The reviewer must analyze these confidentiality and
availability limits and state whether they are compatible with the product's
privacy promise; aggregate-only software rules do not prevent collusion among
all three trustees.

The review must also account for:

- A malicious authority or bidder choosing keys, ciphertexts, pool membership,
  or timing to learn information from the released total.
- A malicious or compromised trustee sending malformed, inconsistent, or
  selectively withheld messages.
- Publicly observable accepted counts, totals, transfer timing, destinations,
  and repeated releases.
- Differencing between pools that share bidders, trustees, keys, or epochs.
- A single prover receiving all bid openings or claim secrets. This is outside
  the acceptable design; the existing single-prover SP1 shortcut is rejected.
- Denial of service and the behavior when fewer than the required trustees are
  available.

Where privacy depends on honest behavior, state the assumption precisely. Do
not describe threshold cryptography as protecting against a colluding quorum.

## Questions for the reviewer

### Key establishment and exact Token-2022 mapping

- Starting from the pinned SDK and Token-2022 source, derive the exact
  encryption/decryption equation and verify what the prototype calls `H/s`.
- Do three sequential inverse-factor transforms produce a key that is
  byte-for-byte and mathematically compatible with that equation?
- What key ceremony, participant authentication, factor-custody, complaint,
  abort, and recovery behavior are required for this multiplicative 3-of-3
  model? Do not assume a Shamir DKG or Lagrange reconstruction.
- How are zero or invalid joint secrets, invalid curve points, participant
  equivocation, and key-epoch changes detected?
- Can every trustee's public verification share be checked without revealing
  its secret share?

### Aggregate construction and decryption

- Is homomorphic addition of the exact low and high auditor ciphertexts valid
  for the pinned dependency and Token-2022 representation?
- What on-chain state must be retained so each successful transfer contributes
  exactly once, atomically with the CPI and accepted-bid state?
- Which fields must be frozen at finalization, and what digest uniquely
  authorizes a decryption request?
- Which proof system and equations make each of the three sequential
  decryption transforms verifiable?
  Are challenges domain-separated over the full finalized digest, trustee,
  epoch, and component?
- Can any single trustee, proof operator, or coordinator learn an individual
  amount from its view? What is leaked by public partial shares and transcript
  metadata?
- How is the final third transform checked against the exact low/high ciphertext
  points, and how are the bounded plaintext components decoded?

### Integer decoding, bounds, and release policy

- Do the recorded per-bid and maximum-bid-count bounds guarantee unique decoding
  of both accumulated components with no modular wraparound?
- Are every intermediate and final operation bounded, including the
  `high_total << 16` reconstruction?
- What minimum participation and cross-pool release policy is necessary?
  Explain why the chosen policy resists singleton and differencing attacks;
  do not rely on a count threshold without analyzing overlapping cohorts.
- Should trustee keys or release budgets be scoped across auctions to prevent
  repeated or overlapping aggregate queries?

### Operations and implementation boundary

- What authenticated transcript, message format, participant registry, and
  durable state are required for reproducible verification?
- What are the safe abort, retry, key rotation, and cancellation/refund rules?
- What compute, account-size, and transaction-size budgets are required on the
  target Solana runtime?
- What exact Token-2022 and DBC binaries and runtime tests are required before
  any funding or settlement path can be enabled?

## Required review deliverables

Return a written review containing:

1. A go/no-go decision and the exact privacy and collusion guarantees supported.
2. A protocol specification with equations, message formats, state transitions,
   domains, transcript binding, and participant roles.
3. The multiplicative 3-of-3 key-ceremony security model, transform-verification
   method, complaint and abort handling, and key-epoch policy.
4. A proof argument or precise reduction for key secrecy, partial-share
   correctness, aggregate binding, and bounded decoding.
5. An explicit analysis of quorum collusion, lone-bid disclosure, and
   cross-pool/epoch differencing.
6. A list of implementation changes, adversarial tests, runtime tests, and
   independent audits required before the compile-time gate may change.
7. Findings with severity, exploit conditions, and required remediation. If a
   claim cannot be supported, identify it as an unresolved assumption.

## Acceptance and stop conditions

Do not enable the selected direction merely because the review finds
homomorphic addition mathematically valid. Proceed only after the reviewer
approves the complete protocol and the product owner accepts its explicit
collusion and release-policy limits.

Keep `AGGREGATE_DECRYPTION_PROOF_READY` false unless all of the following are
true:

- The exact key mapping and complete 3-of-3 key-ceremony protocol have
  independent approval.
- The protocol and threat model define all participant, transcript, abort, and
  release-policy behavior.
- The implementation binds the public total to every accepted transfer and
  verifies the finalized aggregate's threshold shares.
- Adversarial and boundary tests pass, including replay, omitted/duplicated
  entries, invalid shares, trustee aborts, overflow, and differencing attempts.
- Solana runtime tests establish CPI atomicity and the exact amount withdrawn.
- Independent cryptographic and program audits are complete, and the deployed
  Token-2022/DBC binaries match the reviewed runtime assumptions.

If the review cannot justify the privacy claim under the required collusion
model, record a no-go and do not weaken the gate to meet a deployment schedule.

## Evidence package

Review these files and verify all version-sensitive claims against their pinned
sources:

- [Selected design](AGGREGATE_DECRYPTION_DESIGN.md)
- [Project threat model](../../threat_model.md)
- `onchain/Cargo.toml` and `onchain/Cargo.lock`
- `onchain/src/processor.rs` and `onchain/src/state.rs`
- `proof/relation/src/lib.rs`
- Pinned Token-2022, Solana ZK SDK, and confidential-transfer ciphertext
  arithmetic source

The current test fixtures are synthetic. No reviewer should request real private
keys, production trustee shares, or bid openings to assess this design.