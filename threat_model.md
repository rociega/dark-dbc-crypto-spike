# Threat Model

## Project Overview

This model scopes `launch-shield/`, a Rust/Solana auction prototype. Its active
path is a public-reveal MVP; `launch-shield/private-claims-prototype/` is a
separate research-only path using SP1 proofs, Token-2022 confidential transfers,
private claim notes, and Meteora DBC settlement. Users include auction
authorities, bidders, proof operators, trustees, claim recipients, and
settlement operators.

The workspace's Express/PostgreSQL API server and component-preview sandbox
are outside this model; they are not assumed to participate in Launch Shield's
fund-moving path and should be assessed separately if they are connected.

The private-claims path is unaudited and not deployable. Its funding and
settlement handlers remain fail-closed until a reviewed aggregate-decryption
protocol exists. The local DBC source build does not match the recorded Devnet
executable, and runtime CPI compatibility has not been established.

## Assets

- **Bid amounts and openings** — amounts, commitment randomness, and claim
  secrets must not be exposed to a centralized prover or a single trustee.
- **Trustee key shares and DKG transcripts** — compromise or equivocation can
  expose individual bids or invalidate the auditor key.
- **Escrowed assets** — confidential Token-2022 funding balances and classic
  SPL output tokens must not be withdrawn, redirected, or double-spent.
- **Accepted-bid and claim state** — roots, transfer contexts, note
  commitments, and domain-separated nullifiers determine eligibility and replay
  protection.
- **Settlement configuration** — funding/output mints, vaults, total amounts,
  DBC pool/config, token program IDs, and CPI account order determine where
  value moves.
- **Program and proof integrity** — deployed program bytes, SP1 guest/verifier
  identities, DBC build provenance, and upgrade authorities must match reviewed
  source and configuration.
- **Public transaction metadata** — sender accounts, destinations, timing, and
  redemption amounts may link otherwise separate claim and redemption records.

## Trust Boundaries

- **Bidder client to Solana** — clients construct statements and proofs, but
  accounts, signatures, proof contexts, and amounts supplied by a client remain
  untrusted until checked on-chain.
- **Launch Shield to Token-2022 and SPL Token** — CPIs cross into independently
  deployed programs. Program IDs, owners, mint/vault relationships, CPI data,
  and signer PDAs must be validated.
- **Launch Shield to Meteora DBC** — settlement depends on the deployed DBC
  executable, pool/config accounts, token-program interface, account ordering,
  and atomic rollback.
- **Trustee network to public chain** — private shares and DKG transcripts are
  held by separate operators; public decryption-share submissions must be
  bound to one frozen aggregate and verified on-chain.
- **Source/build to deployed programs** — a reviewed Git commit or successful
  SBF build does not prove it produced the executable deployed on Devnet.
- **Research prototype to production** — test-domain relations, synthetic
  fixtures, host tests, and simulated shares must not be treated as production
  cryptography or runtime evidence.

## Scan Anchors

- Active on-chain program: `launch-shield/program/src/lib.rs`,
  `launch-shield/program/src/processor.rs`, and `launch-shield/program/src/state.rs`.
- Read-only deployment provenance check:
  `launch-shield/scripts/check_dbc_devnet.py`.
- Private-claims research code:
  `launch-shield/private-claims-prototype/`; do not treat it as production.
- DBC CPI construction:
  `launch-shield/private-claims-prototype/onchain/src/dbc.rs`.

## Threat Categories

### Spoofing

An attacker can supply lookalike accounts, token programs, mints, vaults, DBC
configs, or proof-context accounts. On-chain handlers MUST verify signer
identity, account owners, expected PDAs, executable program IDs, mint/vault
relationships, and proof-context hashes. Trustee contributions MUST be
authenticated against the DKG's registered participant identities and
verification shares.

### Tampering

An authority, bidder, relayer, or malicious program may try to change a bid
statement, substitute an auditor ciphertext, omit an accepted transfer, alter
the aggregate, replay a proof, or change settlement accounts. The accepted
state and any future ciphertext accumulator MUST update atomically only after
the Token-2022 CPI succeeds. Finalization MUST freeze the accepted count,
commitment root, transfer-context root, auditor key, and aggregate ciphertext.
The public total MUST come from a verified threshold decryption of that exact
state, not an authority-provided initialization value.

### Repudiation

Trustees may deny or dispute which key epoch, accepted set, or aggregate they
approved. DKG transcripts, finalized aggregate digests, trustee identities,
proofs of correct partial decryption, and state transitions MUST be
domain-separated, reproducible, and publicly auditable without exposing
individual bid openings.

### Information Disclosure

A centralized prover given all openings can learn individual amounts and claim
secrets. A threshold aggregate design must release only the final authorized
sum and must not provide per-bid or subset decryption. A 2-of-3 threshold does
not protect against two colluding trustees. Public totals reveal a lone bid,
and overlapping aggregates can leak through differencing; minimum-participation
and release policies are required. Separate claim/redemption nullifiers prevent
direct identifier reuse, but transaction sender, destination, amount, and
timing can still re-link activity.

### Denial of Service

Proof verification, proof-context accounts, trustee failures, and settlement
CPIs can consume compute or block progress. All loops and proof payloads MUST
be bounded; trustee abort/retry rules and safe cancellation/refund behavior
MUST be defined before funds are accepted. Runtime tests MUST cover compute
limits and atomic rollback.

### Elevation of Privilege

An authority or compromised upgrade key could change program behavior, choose
an unsupported total, or redirect settlement. Production activation MUST
remove authority control over the aggregate total, constrain config/mint/vault
selection, and govern upgrades. No deployment may rely on a DBC source build
that does not match the executable and tested runtime behavior. The recorded
Devnet DBC upgrade authority is a System Program-owned, data-free account; its
controller and any off-chain multisig governance are not established by that
account state.

## Required Guarantees

- No single operator or prover receives all bid openings or claim secrets.
- Every accepted transfer contributes exactly once to the frozen aggregate.
- Every published total is publicly verifiable against the frozen accepted set.
- No private-claims initialization, funding, or settlement occurs while the
  aggregate proof gate is false.
- Claim and redemption nullifiers remain domain-separated and replay-resistant.
- Token and DBC CPIs use the reviewed program IDs, accounts, and compatible
  deployed binaries.
- Production activation requires independent cryptographic and program audits,
  plus runtime CPI tests; host tests and Devnet fingerprints alone are
  insufficient.