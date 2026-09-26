# Threshold-crypto implementation gate

**Review date:** 2026-09-26  
**Decision:** No candidate found in this targeted scan is a safe drop-in. Do not start DBC settlement integration on the strength of these candidates.

## Required property

The fixed-eight design relies on the Token-2022 confidential-transfer ElGamal key format. In the pinned SDK, the public key point is derived as H/s, not the usual additive form G*s. The system must create a 2-of-3 key without any trustee learning the complete secret, derive a compatible public key, and retain threshold shares that can decrypt only the public aggregate Q. The local masked-inversion test is a centrally simulated arithmetic transcript, not a DKG or a malicious-secure MPC protocol. See the [spike README](https://github.com/rociega/dark-dbc-crypto-spike/blob/main/README.md) and [host test](https://github.com/rociega/dark-dbc-crypto-spike/blob/main/src/lib.rs).

## Candidate scan

This is a targeted repository/README scan, not a claim that no suitable implementation exists anywhere.

Additional GitHub repository searches for Ristretto threshold DKG, distributed inversion MPC over Shamir shares, and malicious threshold encryption over Ristretto returned no repository hits. GitHub repository search is incomplete, so this is a search signal, not proof that no implementation exists.

| Candidate | What its repository documents | Why it does not pass this gate |
|---|---|---|
| [OpacityLabs/opacity-ferveo](https://github.com/OpacityLabs/opacity-ferveo/blob/dev/README.md) | Synchronous DKG and threshold decryption over BLS12-381; maintained for opacity-stack. Its README says it has not been independently audited and general-purpose use is not a goal. | Different curve and key representation from the Token-2022 ElGamal key. It is not a drop-in implementation of the required H/s distributed inversion. |
| [renegade-fi/ark-mpc](https://github.com/renegade-fi/ark-mpc/blob/main/README.md) | Malicious-secure SPDZ-style two-party MPC. The README example requires an external Beaver preprocessing source. | A generic two-party MPC framework, not a ready 2-of-3 DKG or reviewed distributed-inversion protocol for this key mapping. Preprocessing and protocol composition remain security-critical. |
| [HeyPromaRoy/Threshold-ELGamal](https://github.com/HeyPromaRoy/Threshold-ELGamal/blob/main/README.md) | Its README identifies it as an applied-cryptography course project, using 3072-bit safe-prime parameters and describing trusted-dealer or DKG-simulation setup. | Different group and key format; not evidence of a production-ready, malicious-secure, Token-2022-compatible protocol. |
| [randa-mu/dcipher](https://github.com/randa-mu/dcipher) | Threshold-cryptography project with BLS-oriented components; GitHub marks the repository archived. | Archived and not compatible with the required Token-2022 ElGamal point/encoding. |

No candidate above is being recommended as a dependency. The scan does not establish the audit status of ark-mpc or the academic project; their repository descriptions simply do not establish the exact protocol and assurance this project needs.

## Go/no-go criteria before settlement code

1. **Key generation:** Specify and independently review a malicious-secure 2-of-3 DKG for the exact scalar field and threat model, including verification shares, authenticated transcript binding, fresh randomness, and abort/complaint behavior.
2. **Distributed inversion:** Demonstrate that parties derive shares of 1/s and the exact Token-2022-compatible H/s public key without opening s or 1/s. Preserve the original shares of s for aggregate decryption. The current centralized arithmetic fixture does not meet this criterion.
3. **Token-2022 compatibility:** The lightweight host harness at [token-2022-processor-test/src/lib.rs](token-2022-processor-test/src/lib.rs) passes 4/4. One test initializes the mint and checks the stored fixed-test-scalar auditor key; a second checks the CPI-compatible `inner_transfer` builder; a third locally generates and verifies SDK proof data, supplies synthetic proof-context accounts to `verify_transfer_proof`, confirms exact auditor-ciphertext extraction, and rejects a mutated proof-type tag. A fourth directly invokes Token-2022's `Processor::process` on a confidential transfer using in-memory mint/token-account states and synthetic proof-context accounts derived from locally verified proof fixtures. It manually seeds the source's starting available-balance ciphertext, rejects separate one-byte changes to the low and high auditor ciphertexts before either token account changes, then accepts the exact pair and checks the updated source ciphertext, destination pending ciphertexts, and credit counter. It then processes `ApplyPendingBalance`, confirms the destination's available ciphertext equals full-value encryption with the combined opening, clears pending state, and leaves the public token amount at zero. This exercises Token-2022's transfer processor path, but not the proof program, System Program account creation, validator runtime, or a CPI; the accounts/contexts are synthetic and the starting balance is not established by a deposit. All ElGamal keys are test scalars; this is not DKG. The separate ProgramTest remains unverified because of this runner's memory limit; even when it runs, a live transfer/CPI test will still be required.
4. **Privacy and custody:** Prove that the accepted private amount is linked to its exact ciphertext, while preserving the rule that no claim is publicly linked to its source bid/leaf. Participation records may identify bidders; their later claims must remain unlinkable. Prove the program-owned vault and single DBC swap conserve assets, and claims are redeemable to arbitrary destinations.
5. **On-chain verification:** Fix proof formats, transcript domains, trustee verification-key registry, and bounded public-aggregate recovery, then test the verifier against negative/adversarial vectors.

**Current decision:** Hold DBC settlement implementation until criteria 1-3 have a credible pass and criteria 4-5 have a reviewed construction. Keep the eight-note scope and do not relax the no-single-trustee assumption to meet the deadline.
