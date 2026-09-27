# Dark DBC: private bids, public batch result

## Confirmed privacy boundary

Individual bids must stay private and there must never be a public link from a
bid commitment to its eventual holding. The aggregate spend and clearing
price may be public after settlement. Claims live in a shielded pool and may
later be redeemed to any address through a commitment/nullifier proof. For
ordinary DBC-token redemption, the final transfer's amount and destination
are public; the shielded proof prevents linking them to the originating bid.

For ordinary DBC SPL/Token-2022 output, a later redemption transaction still
shows the redemption amount and destination; the nullifier proof hides which
bid note was spent. This design promises unlinkability, not hidden amounts in
the final public token transfer. If the amount itself must also remain hidden
at redemption, DBC's output token must support confidential transfers.

A public `reveal_bid(amount, ...)` is not acceptable: instruction arguments
are public. A transparent per-bid escrow balance or plaintext
`escrowed_amount` is also a leak. Public aggregate state such as total spend
and the resulting clearing price is allowed after settlement.

The attached code is a scaffold only. Its Poseidon function returns zero,
its TypeScript hash is undefined, and its confidential-transfer, DBC, and
bond functions are placeholders.

## DBC is a separate constraint

In Meteora's published `dynamic-bonding-curve` main branch, pool
initialization sets `activation_point` from the current slot or timestamp.
The swap path reads the current point and uses the pool activation point in
rate-limiter logic; the inspected path does not use it as a future swap gate.
Meteora's repository describes DBC pools as immediately tradable through
integrations.

This is evidence about the published source branch, not proof that every
deployed version is identical. Check the deployed program ID and matching
IDL/source before relying on it. An external wrapper cannot block direct
calls to DBC's public swap instruction. The pool therefore must not exist
while bids are being submitted; create it only for post-window aggregate
execution, ideally atomically with the first aggregate swap.

References:

- [DBC pool initialization](https://github.com/MeteoraAg/dynamic-bonding-curve/blob/main/programs/dynamic-bonding-curve/src/instructions/initialize_pool/process_initialize_virtual_pool_with_token2022.rs)
- [DBC swap path](https://github.com/MeteoraAg/dynamic-bonding-curve/blob/main/programs/dynamic-bonding-curve/src/instructions/swap/process_swap.rs)
- [DBC quote-mint validation](https://github.com/MeteoraAg/dynamic-bonding-curve/blob/main/programs/dynamic-bonding-curve/src/utils/token.rs)
- [DBC TokenBadge authorization](https://github.com/MeteoraAg/dynamic-bonding-curve/blob/main/programs/dynamic-bonding-curve/src/lib.rs)
- [Meteora DBC repository](https://github.com/MeteoraAg/dynamic-bonding-curve)

## Fixed-capacity hackathon flow

Use a fixed `MAX_BIDS = 8` for the demo: eight bid commitments, at most eight
claim notes, a depth-three Merkle tree, and no note splitting or merging.
This is a deliberately bounded anonymous set, not a general-purpose
arbitrary-scale mixer.

### Working funding boundary

Ordinary USDC/SOL top-ups into the project-owned confidential bid-token
reserve happen before the auction and are not themselves bids. During the
commit window, do not accept a fresh exact-value wrap as bid funding; the bid
is the later confidential transfer of `a_i` bid tokens. At settlement, release
only public aggregate `Q` from the backing reserve as DBC's ordinary quote
asset.

This hides each bid amount from public auction data, but does not erase the
public history of top-ups. If a top-up equals a later bid and can be linked to
the same bidder, observers may infer the bid. Stronger funding unlinkability
needs a separate identity/relayer or shielded on-ramp; the custom token alone
does not provide it. The reserve must also enforce 1:1 collateralization and
restrict bid-token mint/burn authority to the adapter.

1. **Commit.** Each bidder submits a domain-separated commitment plus the
   public fixed SOL bond. The commitment binds program ID, auction PDA,
   bidder, amount, bid randomness, and claim-note secret. No plaintext amount
   is passed. The public bid PDA may identify who participated, but it must
   not be linked to a claim-note leaf.
2. **Confidential funding.** Use a project-owned Token-2022 confidential
   bid-token mint, distinct from DBC's quote mint. Bidders transfer this token
   from pre-funded confidential balances into the auction's confidential
   balance. A custom proof must bind each hidden transfer amount to its bid
   commitment; the stock confidential-transfer proof alone does not establish
   that link. This removes TokenBadge approval from DBC's critical path:
settlement releases only public aggregate `Q` as the ordinary SPL quote
   asset that the DBC pool accepts. The published DBC helper allows ordinary
   SPL quote mints or Token-2022 mints with metadata extensions by default;
   non-metadata extensions need a TokenBadge, whose creation requires a
   privileged operator. The adapter keeps the confidential mint out of DBC
   entirely.

   The bid token needs a collateral/redemption adapter. A bidder who wraps
   ordinary USDC or SOL immediately before bidding does **not** get hidden
   funding: SPL transfers and Token-2022 `deposit(amount)` expose that
   amount. For bid-size privacy, users need already-funded confidential
    balances or a separate unlinkable funding path; the adapter cannot claim
    that a fresh per-bid wrap is private. The bid vault must not rely on a
    single ElGamal-secret holder. The leading candidate is client-generated
    per-bid proofs plus threshold decryption of Token-2022 auditor ciphertexts,
    so a trustee quorum can publish aggregate `Q` without any one trustee
    decrypting individual bids. Threshold-key compatibility and custody remain
    blockers, not reasons to weaken the privacy requirement.
3. **Aggregate.** Each accepted funded bid contributes a client-proven
   Token-2022 auditor ciphertext pair for `a_i`. After commits close,
   verifiable threshold decryption of the homomorphic sum publishes `Q`; no
   plaintext individual bid is revealed. The committee's collusion threshold
   is an explicit assumption, and the program accepts decryption shares only
   for the aggregate ciphertext.
4. **One real DBC swap.** After the commit window closes, release exactly
   public aggregate `Q` from the ordinary quote reserve only after the
   per-bid ZK links and threshold decryption establish that the accepted
   confidential bid-token inputs sum to `Q`. Treat those bid-token inputs as
   consumed/locked in the auction vault; do not depend on a single key holder
   decrypting the vault and withdrawing `Q`.
   Execute one swap against the real DBC pool. The program-owned base-token
   vault receives all output `Y`; no bidder executes an individual DBC swap.
   Since DBC does not gate a pre-existing pool, create/initialize the pool
   only at settlement and atomically execute the aggregate swap in the same
   transaction. Keep the base-mint signer/key unpublished until then so a
   third party cannot initialize that pool early.
5. **Shielded claims.** Each bidder locally computes
   `value_i = floor(amount_i * Y / Q)` and generates a ZK note proof against
   the funded-bid root. A relayer batches and shuffles up to eight proofs and
   note commitments into the claim root. No batcher receives amount witnesses;
   never store or emit a bid-PDA-to-note-index mapping. Since
   `sum(amount_i) = Q`, the allocation formula guarantees total notes do not
   exceed `Y`; unallocated rounding dust stays in the named vault.
6. **Bond settlement.** Return bonds for valid funded bids and handle
   unfunded or invalid commitments through a separate, permissionless path.
   Never mark a bond settled before the SOL transfer succeeds.

Each note commits to its hidden value, auction/asset domain, and a
claim-secret/nullifier-secret known to its owner. The claimant supplies a
Merkle-membership/nullifier proof and an arbitrary destination. The program
rejects a spent nullifier and transfers that note's value from the pooled
vault. The transaction is not linked to the original bid account. Redemption
amount and destination are visible for ordinary DBC tokens; if those must
also be hidden, the output token needs confidential transfers instead.

For the fixed eight-note MVP, `ClaimPool` needs only the auction/asset IDs,
program-owned vault, Merkle root, leaf count, and a fixed-size spent-nullifier
set plus registration status. A note-registration proof checks unique
nullifier registration; a redemption proof checks note membership, nullifier
derivation, available pooled balance, and one-time spend. Full-note redemption
only; omit splitting, merging, and a general-purpose mixer.

## Fixed-eight client-proof contract

Do not ask one settlement prover to construct a proof from all eight amounts.
The candidate path is one client-generated funding proof per bid, the
Token-2022 confidential-transfer auditor ciphertext encrypted to a DKG
threshold key, and one client-generated claim-note proof per bid. The
settlement program verifies the individual proofs and publishes only the
threshold-decrypted sum. This avoids centralizing all amount witnesses,
subject to the explicit trustee-collusion assumption below. If the Token-2022
auditor key cannot use the DKG key format, an app-level ciphertext can be a
fallback only if a ZK proof links it to the exact transfer ciphertext.

**Funding-proof public inputs:** auction/program domain, bidder-bound bid
commitment, accepted confidential-transfer proof-context state, auditor
ciphertext pair `A_i = (A_i^lo, A_i^hi)`, token mint/vault identifiers, and
the configured threshold auditor public key.

**Funding-proof private witness:** amount `a_i`, commitment randomness,
claim/nullifier secret, low/high amount components `lo_i`/`hi_i`, and their
auditor ciphertext randomness.

**Funding-proof constraints:**

- `1 <= a_i <= MAX_BID_AMOUNT`; the commitment opens to `a_i` and the
  bidder's claim/nullifier secret.
- For the MVP, `MAX_BID_AMOUNT <= 2^32 - 1`; this conservative cap keeps the
  eight-bid aggregate below `2^35` for bounded discrete-log recovery.
- `a_i = lo_i + (hi_i << 16)`, `0 <= lo_i < 2^16`, and
  `0 <= hi_i < 2^32`.
- `A_i^lo` encrypts `lo_i` and `A_i^hi` encrypts `hi_i` under the auction's
  threshold auditor public key. The Token-2022 transfer proof must verify
  these are its actual auditor ciphertexts for this transfer.
- The accepted Token-2022 confidential transfer moves that same amount into
  the auction's confidential bid-token vault.
- Transfer, commitment, and ciphertext are bound to this auction and cannot be
  replayed or counted twice.

The circuit must prove equality across the commitment and Token-2022 auditor
ciphertext pair accepted by the confidential-transfer proof. Verifying a
Token-2022 transfer proof and a commitment proof independently does not
establish that they use the same amount.

**Aggregate settlement:** combine each bidder's pair as
`A_i = A_i^lo + (2^16 * A_i^hi)` using the Token-2022 proof-generation
library's ciphertext-combination rule, then sum `A_i` for exactly the accepted
funded bids. A configured `t-of-m` trustee set publishes verifiable partial
decryptions of this single aggregate ciphertext only. The decrypted group
element represents `Q * G`; with `MAX_BID_AMOUNT <= 2^32 - 1`, the fixed-eight
bound is `Q < 2^35`, so bounded discrete-log recovery needs about 186,000
baby-step entries. Verify that `Q * G` matches the decrypted point and publish
only `Q`, not the low/high component sums. Each trustee sees per-bid
ciphertexts, but fewer than `t` colluding trustees cannot decrypt them. A
quorum can decrypt an individual ciphertext if it chooses to collude, so this
is a threshold trust assumption, not trustlessness. No single trustee can
learn all bids, and no single prover receives all amount witnesses.

**Claim-note proof public inputs:** funded-bid commitment root, public `Q`,
public DBC output `Y`, output note commitment, and a domain-separated public
nullifier. The private witness opens one funded bid commitment, proves its
amount and claim secret, and supplies note randomness.

**Claim-note constraints:**

- The bid is a member of the accepted funded-bid root, but its index,
  bidder key, amount, and commitment opening remain private.
- `v_i = floor(a_i * Y / Q)`, expressed without division as
  `v_i * Q <= a_i * Y < (v_i + 1) * Q`, with range-checked 128-bit
  intermediates to prevent field/integer wraparound.
- The output note commits to `v_i` and the secret nullifier key; its public
  nullifier is deterministically bound to the funded bid so one bid cannot
  register multiple notes.
- The note is appended among at most eight outputs without publishing a
  bid-PDA-to-leaf mapping. A relay/batcher should submit proofs in a shuffled
  batch to reduce transaction-level correlation; the proof hides the source
  bid cryptographically.
- Because all `a_i` are positive and sum to `Q`, the allocation formula
  guarantees `sum(v_i) <= Y`; `Y - sum(v_i)` remains explicit rounding dust.

**Spend-proof public inputs:** current claim root, public nullifier, public
redemption amount, destination, asset mint, and pool domain. The private
witness proves note membership, derives its nullifier, and shows the public
redemption amount equals the hidden note value. The program rejects a
repeated nullifier before signing the vault transfer. The source bid PDA is
not an input.

This replaces a whole-batch witness proof with bounded per-bid proofs plus
threshold decryption. It is still a proposed protocol, not an implemented or
verified cryptographic construction. The fixed proof statements must bind the
actual Token-2022 proof-context state and fit Solana's verifier and compute
limits.

The Token-2022 confidential-transfer API exposes an encrypted `transfer`
instruction with proof inputs, while `deposit` and `withdraw` accept an
explicit `amount`. So a confidential bid-token transfer can hide the bid
amount, and the public reserve release can reveal only the permitted
aggregate `Q`. But a fresh wrap from ordinary USDC/SOL exposes the wrap
amount; the confidential-mint/burn extension does not hide the underlying
public-asset transfer into the reserve. Token-2022 also does not supply the
custom proof that links each bid-token transfer to a Poseidon commitment or
proves the auction allocation formula.

The Token-2022 interface exposes an optional mint-level auditor ElGamal
public key and transfer-level low/high auditor ciphertexts. The 0.6.1
proof-generation docs specify a 16-bit low component and 32-bit high component,
and provide `try_combine_lo_hi_ciphertexts` to combine them homomorphically.
Prefer these transfer ciphertexts over a second application ciphertext if the
mint accepts the DKG aggregate key. For the fixed-eight MVP, cap each bid at
`2^32 - 1`; then the combined aggregate encrypts a value below `2^35`, making
bounded discrete-log recovery practical while publishing only `Q`. The
auditor-key/DKG compatibility and threshold-decryption verifier remain
unverified.

References:

- [Token-2022 confidential transfer](https://docs.rs/spl-token-2022/latest/spl_token_2022/extension/confidential_transfer/instruction/fn.transfer.html)
- [Token-2022 confidential deposit](https://docs.rs/spl-token-2022/latest/spl_token_2022/extension/confidential_transfer/instruction/fn.deposit.html)
- [Token-2022 confidential withdrawal](https://docs.rs/spl-token-2022/latest/spl_token_2022/extension/confidential_transfer/instruction/fn.withdraw.html)
- [Token-2022 confidential mint/burn](https://docs.rs/spl-token-2022/latest/spl_token_2022/extension/confidential_mint_burn/index.html)
- [Token-2022 interface 3.1.2 confidential-transfer mint initialization](https://docs.rs/spl-token-2022-interface/3.1.2/spl_token_2022_interface/extension/confidential_transfer/instruction/fn.initialize_mint.html)
- [Token-2022 interface 3.1.2 confidential transfer builder](https://docs.rs/spl-token-2022-interface/3.1.2/spl_token_2022_interface/extension/confidential_transfer/instruction/fn.transfer.html)
- [Token-2022 interface 3.1.2 confidential-burn builder](https://docs.rs/spl-token-2022-interface/3.1.2/spl_token_2022_interface/extension/confidential_mint_burn/instruction/fn.confidential_burn_with_split_proofs.html)
- [Confidential-transfer proof-generation flow, version 0.6.1](https://docs.rs/spl-token-confidential-transfer-proof-generation/0.6.1/spl_token_confidential_transfer_proof_generation/transfer/)
- [Transfer amount low-component width, 16 bits](https://docs.rs/spl-token-confidential-transfer-proof-generation/0.6.1/spl_token_confidential_transfer_proof_generation/constant.TRANSFER_AMOUNT_LO_BITS.html)
- [Transfer amount high-component width, 32 bits](https://docs.rs/spl-token-confidential-transfer-proof-generation/0.6.1/spl_token_confidential_transfer_proof_generation/constant.TRANSFER_AMOUNT_HI_BITS.html)
- [Combine low/high ElGamal ciphertexts](https://docs.rs/spl-token-confidential-transfer-proof-generation/0.6.1/spl_token_confidential_transfer_proof_generation/fn.try_combine_lo_hi_ciphertexts.html)
- [ElGamal key-generation implementation, version 7.0.1](https://docs.rs/crate/solana-zk-sdk/7.0.1/source/src/encryption/elgamal.rs)

## Host-side cryptography spike

A standalone host-test crate now uses `solana-zk-sdk` 7.0.1,
`solana-zk-sdk-pod` 0.1.2, confidential-transfer proof-generation 0.6.1, and
SHA-512 for a test-only Fiat-Shamir transcript. Seven tests pass for the SDK
ciphertext-pair combination, `PodElGamalPubkey` encoding round-trip,
deterministic 2-of-3 aggregate-decryption arithmetic, candidate
masked-inversion arithmetic, test-only Chaum-Pedersen decryption-share proofs,
and bounded recovery of public `Q < 2^35`.

The spike also found a key-generation blocker: the SDK derives its ElGamal
public key as `H / s` from secret scalar `s`, so public keys generated
independently from ordinary Shamir shares do not interpolate to the required
group public key. A test centrally simulates a candidate degree-reduction step:
it multiplies Shamir shares of `s` and a separately shared random mask `r`,
reshapes the products, publicly reconstructs the masked value `z = s*r`, and
derives shares of `1/s` as `r_i/z`. Interpolating the inverse-share public
points gives the required `H/s`, while original shares of `s` can still
decrypt. This validates algebra only: the test centralizes all shares and
omits authenticated channels, VSS, malicious-participant protections,
robust randomness, abort handling, and a security proof.

Read-only research found no maintained, audited Rust implementation for this
SDK's inverse-secret key map. Standard threshold-ElGamal libraries examined
use the usual `g^s`/`g*s` mapping and are not drop-in compatible. The ordinary
threshold-decryption test also constructs the public key from the full test
secret. Therefore, the distributed-inversion/DKG remains an explicit
production go/no-go blocker, not a solved component.

The harness also implements a test-only Chaum-Pedersen equality-of-discrete-log
proof for a partial decryption, bound to the auction domain, trustee-set ID,
aggregate key, trustee index, and aggregate ciphertext. It tests valid proofs
and rejects altered context, trustee set, key, trustee index, handle, and
partial decryption. The proof uses fixed test nonces and host-side point
operations; it is not audited, serialized for chain use, or measured in Solana
compute units. A production verifier must also authenticate the verification
share against the DKG registry, recompute the exact accepted-bid ciphertext
aggregate, derive Lagrange coefficients from the registered trustee set, and
reject individual-ciphertext or replay attempts.

This is not a local-validator test. It does not establish that a real
Token-2022 mint accepts the candidate key, verify the transfer proof-context
state, provide malicious-secure DKG/share multiplication, or prove vault
custody. Those remain go/no-go blockers.

The separate `protocol-spike::claim_structure` module now models the fixed
depth-three tree and eight-slot nullifier registration/spend state. It checks
host-side path construction, incremental root updates, registered leaf count,
mutation rejection, atomic note/nullifier state updates, unique nullifier
registration, and one-time spend transitions. Its tree accepts a caller-supplied
pair hash; the SHA-256 test hash is only test scaffolding, not the selected
circuit hash. The witness exposes its index and sibling path, and the registry
does not derive nullifiers or prove note ownership. This is not an unlinkable
claim proof, on-chain state machine, or redemption implementation.

## Cryptographic blockers to resolve

The threshold-encryption route above is the leading candidate because each
bidder proves only their own amount; no ordinary batch prover receives all
eight witnesses. It must not be represented as solved until each blocker below
is verified:

 0. **Pin the deployment stack.** The host prototypes now pin their Rust
    dependencies, and the processor harness aligns Token-2022 9.0.0 with
    Solana 2.3.13. That does not select or validate the eventual cluster,
    Anchor/DBC program, Token-2022 interface, or proof-generation deployment
    stack. Pin mutually compatible versions before writing settlement or
    circuit code; do not assume the latest crate matches the target cluster.
    Prefer the Token-2022 auditor ciphertext pair as the encrypted amount if a
    DKG public key is accepted for the mint's auditor key; test this before
    adding a separate application ciphertext.
1. **Token-2022 linkage proof.** The existing Token-2022 proof flow verifies
   confidential token operations; it is not a general-purpose auction
    circuit. Implement and test a per-bid ZK relation binding the same bounded
    `a_i` to the bid commitment and the exact auditor ciphertext pair accepted
    by the confidential-transfer proof. The curve/field compatibility,
    ciphertext encoding, circuit cost, and public inputs for this relation
    are unverified.
2. **Threshold key and aggregate decryption.** Specify and security-review a
   malicious-secure DKG/distributed-inversion protocol or another proven
   construction compatible with Token-2022's `PodElGamalPubkey`,
   trustee verification keys, `t-of-m` policy, low/high ciphertext
   combination, and verifiable partial-decryption checks. The SDK's public-key
   map is `H / s`; a plain Shamir DKG does not directly produce the required
   public key from interpolated share public keys. The program must accept
   partial decryptions only for the aggregate of the eight accepted bids, not
   individual bids, and verify that public `Q` matches the decrypted aggregate
   point. Fewer than `t` colluding trustees must not recover a bid; `t` or more
   can, so trustee independence is an explicit privacy assumption. The host
   harness tests candidate masked-inversion algebra and Chaum-Pedersen share
   proofs only; it is not an audited DKG or an on-chain verifier. No maintained,
   audited Rust library matching the SDK's `H / s` key map was found.
3. **Token custody.** Prove that the accepted confidential bid-token inputs
   are consumed or irreversibly locked when `Q` is released. Do not assume a
   single ElGamal-secret holder can withdraw from the vault. Token-2022
   confidential balance updates, transfer authority, and burn/retirement
   semantics for this exact vault/key setup remain unverified.
4. **Verifier and limits.** Select a ZK system with an on-chain Solana
   verifier and measure per-bid funding proof, claim proof, threshold-share
   verification, account count, and compute use for all eight slots.
5. **Claim anonymity.** Validate the fixed-depth funded-bid root and
   nullifier set, and submit note proofs through a relay/batched shuffle so
   the transaction submitter does not expose the bidder-to-note relationship.

ZK protects witnesses from verifiers, not from a prover that receives those
witnesses. Funding and claim proofs must therefore be generated per bidder;
proofs may be batched only after they are generated. Do not replace this with
a centralized settlement service holding all amounts or one operator holding
the bid-vault ElGamal secret. If threshold encryption or the Token-2022 link
cannot be made to work, the fallback is a genuine distributed/MPC proof
generation design—not a trusted single-party prover.

The attached Poseidon call cannot do this: a hash commitment is not a proof
of funding or correct settlement. The chosen proof system must have a
practical Solana verifier and fit transaction compute/account limits. The
published DBC Token-2022 pool initializer initializes its own base mint with
a metadata-pointer constraint; it does not show confidential-transfer
mint-extension initialization. Therefore private transfers of DBC's own
base token are not established. General Token-2022 support does not prove
this extension combination works.

If DBC cannot privately transfer its base token, the privacy-preserving
fallback is to keep the aggregate DBC output in one pooled vault and issue
private notes. This is the user's selected product: holders own private
claims backed by pooled DBC inventory, not direct DBC base-token balances.
They can redeem a note to any address without a public proof linking that
address to the original bid. If redemption amounts must also be hidden, the
current DBC output-token path is insufficient.

## First implementation spike: go/no-go tests

Do not start Anchor settlement or DBC CPI code until these tests pass against
one pinned local-validator/toolchain stack:

1. Produce the compatible threshold auditor public key without any trustee
   learning its secret, then initialize a Token-2022 confidential-transfer
   mint with it. Execute a real confidential transfer and verify that
   Token-2022 accepts the key, auditor ciphertext pair, and proof-context
   state. If the key cannot be represented or authorized, stop and evaluate
   the app-ciphertext fallback.
2. Aggregate the accepted auditor ciphertext pairs for exactly eight
   transfers. Verify the 16-bit low/32-bit high encoding, combine each pair
   into a full-amount ciphertext, and homomorphically sum the eight amounts.
   With the MVP cap, recover `Q < 2^35` from verifiable partial decryptions of
   only the aggregate (about 186,000 baby-step entries with BSGS). Verify that
   the public `Q` matches the decrypted point, reveal no low/high component
   sums, and demonstrate that fewer than `t` trustee shares cannot decrypt
   any individual ciphertext.
3. Generate and verify a client-side ZK proof tying one bidder's
   domain-separated commitment and claim secret to the same amount represented
   by that transfer's auditor ciphertext. Mutate the bidder, amount,
   ciphertext, proof context, and auction domain in turn; every mutation must
   fail verification.
4. Prove the confidential vault balance can be irreversibly consumed/locked
   exactly once while releasing `Q` from the ordinary reserve, without any
   single trustee holding the vault's ElGamal secret. Test replay, failed CPI,
   and partial-settlement recovery.
5. Generate a claim-note proof for `floor(a_i * Y / Q)`, batch and shuffle
   eight notes, then redeem one note to a new address. Verify that public
   inputs reveal no source bid or leaf index, and that a duplicate nullifier
   or altered payout fails.

Record proof bytes, verifier compute units, account count, and transaction
size at one and eight bids. If any privacy, custody, or runtime-limit test
fails, do not weaken the ZK requirement; revise the protocol or stop before
integrating DBC. Only after this gate passes should the project build the
single real DBC swap and pooled output-vault path.

## Account and instruction boundary

Keep the on-chain surface small and fixed:

- `AuctionWindow`: auction/program domain, timing and status, DBC config and
  intended mint/pool addresses, ordinary quote reserve, confidential bid-token
  mint/vault, threshold-key configuration, output vault, fixed bond, public
  `MAX_BID_AMOUNT`, active count (maximum eight), public aggregate `Q`, DBC
  output `Y`, and claim root. It has no per-bid amount.
- `BidCommitment`: auction, bidder, slot, commitment hash, Token-2022 auditor
  ciphertext pair, proof-context reference, verified funding state, and bond
  state. It never stores `amount_i` or a claim-note index.
- `ClaimPool`: auction/asset domain, output vault, depth-three Merkle root,
  leaf count, and eight nullifier slots recording registration/spend state.
  It stores no note values and no bidder-to-leaf mapping.

The intended calls are `pre_fund` (public ordinary-token top-up, outside the
auction), `commit_bid` (commitment plus fixed bond), `fund_bid` (confidential
bid-token transfer, auditor ciphertext pair, and client-generated proof),
`settle_batch` (verify the accepted ciphertext set and threshold decryption
of aggregate `Q`, release `Q`, and execute one real DBC swap),
`register_claim_notes` (up to eight client-generated proofs, relayed and
shuffled into the claim root), and `redeem_note` (full-note
membership/nullifier proof to an arbitrary destination). There is no
plaintext `reveal_bid` and no per-bid DBC swap.

## Required code changes and invariants

- Replace `reveal_bid(amount, blinding_factor)` with commitment, ciphertext,
  and proof inputs; plaintext per-bid amount must never enter instruction
  data or account state.
- Remove plaintext per-bid `escrowed_amount`. Store only commitments,
  ciphertexts, proof state, and explicitly public aggregate values.
- Keep each bid's confidential funds linked to its commitment by a verified
  ZK statement; do not trust client-supplied totals.
- Never publish a bid-to-note mapping. Validate note membership, nullifier,
  destination, mint, vault authority, and one-time spend status at redemption.
- Bind every commitment to the auction/program domain to prevent replay.
  Enforce `1 <= amount_i <= MAX_BID_AMOUNT <= 2^32 - 1`, ensure
  `8 * MAX_BID_AMOUNT <= u64::MAX`, and allow one bid per bidder.
- Derive or pin every vault and check its mint, token program, and authority
  on every instruction.
- Use checked slot arithmetic and bounded durations.
- Set `settled`, `claimed`, and `bond_settled` only after proof verification
  and the associated token/SOL movement succeeds. Every placeholder must
  fail closed, never succeed as a no-op.

## Implementation order

1. Prototype distributed inversion/key generation for the SDK's `H / s`
   ElGamal public-key map; validate whether Token-2022 accepts the resulting
   threshold auditor key and prove confidential-vault custody. Define the
   public pre-funding boundary and DBC quote reserve.
2. Prototype a per-bid proof linking the commitment and Token-2022 auditor
   ciphertext pair for `a_i`; separately prototype aggregate-only threshold
   decryption of the eight accepted ciphertexts into public `Q`.
3. Specify client-generated claim-note proofs, deterministic per-bid
   nullifiers, and relayed/shuffled registration; measure the Solana verifier
   and transaction limits before implementing the full protocol.
4. Update accounts/instructions so bid amounts and bid-to-note links are
   never public.
5. Implement the depth-three claim tree, nullifier set, and full-note
   redemption to arbitrary destinations; omit splitting/merging for the MVP.
6. Integrate the real DBC pool and one aggregate swap at settlement; keep
   the output in the program-owned vault and create no per-bid DBC swaps.