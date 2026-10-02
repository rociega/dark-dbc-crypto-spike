//! Public-total proof relation for one finalized aggregate of accepted bids.
//!
//! The relation verifies the selected multiplicative 3-of-3 key transcript,
//! both aggregate decryption transcripts, and bounded low/high limb decoding.
//! Trustee identity, key custody, and transcript delivery remain external
//! protocol requirements.

use crate::{
    funded_bid_merkle_root,
    threshold::{
        verify_three_of_three_decryption_transcript, verify_three_of_three_key_transcript,
        AggregateComponent, TrusteeDecryptionStep, TrusteeKeyTransformStep, TRUSTEE_COUNT,
    },
    MAX_BID_AMOUNT, MAX_FUNDED_BIDS,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha256};

pub const AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN: usize = 104;
pub const TRUSTEE_KEY_SETUP_PUBLIC_VALUES_LEN: usize = 32;

const FINALIZED_AGGREGATE_DOMAIN: &[u8] = b"launch-shield:private-claims:finalized-aggregate:v1";
const TRUSTEE_KEY_SETUP_PUBLIC_VALUES_DOMAIN: &[u8] =
    b"launch-shield:private-claims:trustee-key-setup-public-values:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrusteeKeySetupStatement {
    pub program_id: [u8; 32],
    pub funding_mint: [u8; 32],
    pub auditor_pubkey: [u8; 32],
    pub key_epoch: [u8; 32],
    pub trustee_ids: [[u8; 32]; TRUSTEE_COUNT],
    pub verification_shares: [[u8; 32]; TRUSTEE_COUNT],
}

impl TrusteeKeySetupStatement {
    pub fn public_values(&self) -> [u8; TRUSTEE_KEY_SETUP_PUBLIC_VALUES_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(TRUSTEE_KEY_SETUP_PUBLIC_VALUES_DOMAIN);
        for field in [
            &self.program_id,
            &self.funding_mint,
            &self.auditor_pubkey,
            &self.key_epoch,
        ] {
            hasher.update(field);
        }
        for field in &self.trustee_ids {
            hasher.update(field);
        }
        for field in &self.verification_shares {
            hasher.update(field);
        }
        hasher.finalize().into()
    }
}

pub fn verify_trustee_key_setup_relation(
    statement: &TrusteeKeySetupStatement,
    steps: &[TrusteeKeyTransformStep; TRUSTEE_COUNT],
) -> bool {
    if statement.program_id == [0; 32]
        || statement.funding_mint == [0; 32]
        || statement.key_epoch == [0; 32]
    {
        return false;
    }
    verify_three_of_three_key_transcript(
        &statement.program_id,
        &statement.funding_mint,
        &statement.key_epoch,
        &statement.trustee_ids,
        &statement.verification_shares,
        steps,
    )
    .is_some_and(|key| key == statement.auditor_pubkey)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateDecryptionStatement {
    pub program_id: [u8; 32],
    pub pool_account: [u8; 32],
    pub auction_id: [u8; 32],
    pub funded_bid_root: [u8; 32],
    pub funding_mint: [u8; 32],
    pub confidential_vault: [u8; 32],
    pub auditor_pubkey: [u8; 32],
    pub key_epoch: [u8; 32],
    pub trustee_ids: [[u8; 32]; TRUSTEE_COUNT],
    pub verification_shares: [[u8; 32]; TRUSTEE_COUNT],
    pub funded_bid_count: u8,
    pub funded_bid_commitments: [[u8; 32]; MAX_FUNDED_BIDS],
    pub accepted_transfer_context_hashes: [[u8; 32]; MAX_FUNDED_BIDS],
    pub aggregate_ciphertext_low: [u8; 64],
    pub aggregate_ciphertext_high: [u8; 64],
    pub total_bid_amount: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateDecryptionWitness {
    pub key_setup_steps: [TrusteeKeyTransformStep; TRUSTEE_COUNT],
    pub low_steps: [TrusteeDecryptionStep; TRUSTEE_COUNT],
    pub high_steps: [TrusteeDecryptionStep; TRUSTEE_COUNT],
    pub low_total: u64,
    pub high_total: u64,
}

impl AggregateDecryptionStatement {
    /// Digest all immutable state that authorizes one aggregate decryption.
    ///
    /// The total is intentionally excluded: the proof derives it from the
    /// aggregate ciphertexts and the bounded low/high component openings.
    pub fn finalized_aggregate_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(FINALIZED_AGGREGATE_DOMAIN);
        hasher.update(self.program_id);
        hasher.update(self.pool_account);
        hasher.update(self.auction_id);
        hasher.update(self.funded_bid_root);
        hasher.update(self.funding_mint);
        hasher.update(self.confidential_vault);
        hasher.update(self.auditor_pubkey);
        hasher.update(self.key_epoch);
        hasher.update(self.funded_bid_count.to_le_bytes());
        for trustee_id in &self.trustee_ids {
            hasher.update(trustee_id);
        }
        for share in &self.verification_shares {
            hasher.update(share);
        }
        for commitment in &self.funded_bid_commitments {
            hasher.update(commitment);
        }
        for context_hash in &self.accepted_transfer_context_hashes {
            hasher.update(context_hash);
        }
        hasher.update(self.aggregate_ciphertext_low);
        hasher.update(self.aggregate_ciphertext_high);
        hasher.finalize().into()
    }

    /// Public values checked by the on-chain verifier after recomputing the
    /// finalized-state digest from its account.
    pub fn public_values(&self) -> [u8; AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN] {
        let mut output = [0; AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN];
        output[..32].copy_from_slice(&self.program_id);
        output[32..64].copy_from_slice(&self.pool_account);
        output[64..96].copy_from_slice(&self.finalized_aggregate_digest());
        output[96..104].copy_from_slice(&self.total_bid_amount.to_le_bytes());
        output
    }
}

pub fn verify_aggregate_decryption_relation(
    statement: &AggregateDecryptionStatement,
    witness: &AggregateDecryptionWitness,
) -> bool {
    let count = usize::from(statement.funded_bid_count);
    if count == 0
        || count > MAX_FUNDED_BIDS
        || statement.program_id == [0; 32]
        || statement.pool_account == [0; 32]
        || statement.auction_id == [0; 32]
        || statement.funded_bid_root == [0; 32]
        || statement.funding_mint == [0; 32]
        || statement.confidential_vault == [0; 32]
        || statement.key_epoch == [0; 32]
        || statement.total_bid_amount == 0
        || statement.total_bid_amount > count as u64 * MAX_BID_AMOUNT
        || statement.funded_bid_root != funded_bid_merkle_root(&statement.funded_bid_commitments)
        || !valid_accepted_entries(statement, count)
    {
        return false;
    }

    let digest = statement.finalized_aggregate_digest();
    let Some(derived_auditor_key) = verify_three_of_three_key_transcript(
        &statement.program_id,
        &statement.funding_mint,
        &statement.key_epoch,
        &statement.trustee_ids,
        &statement.verification_shares,
        &witness.key_setup_steps,
    ) else {
        return false;
    };
    if derived_auditor_key != statement.auditor_pubkey {
        return false;
    }

    let Some((low_commitment, low_handle)) =
        decompress_ciphertext(&statement.aggregate_ciphertext_low)
    else {
        return false;
    };
    let Some((high_commitment, high_handle)) =
        decompress_ciphertext(&statement.aggregate_ciphertext_high)
    else {
        return false;
    };

    let Some(low_opening) = verify_three_of_three_decryption_transcript(
        &statement.program_id,
        &statement.pool_account,
        &digest,
        &statement.key_epoch,
        &statement.trustee_ids,
        &statement.verification_shares,
        AggregateComponent::Low,
        &low_handle,
        &witness.low_steps,
    ) else {
        return false;
    };
    let Some(high_opening) = verify_three_of_three_decryption_transcript(
        &statement.program_id,
        &statement.pool_account,
        &digest,
        &statement.key_epoch,
        &statement.trustee_ids,
        &statement.verification_shares,
        AggregateComponent::High,
        &high_handle,
        &witness.high_steps,
    ) else {
        return false;
    };

    let component_limit = count as u64 * u64::from(u16::MAX);
    if witness.low_total > component_limit || witness.high_total > component_limit {
        return false;
    }

    let Some(low_opening) = CompressedRistretto(low_opening).decompress() else {
        return false;
    };
    let Some(high_opening) = CompressedRistretto(high_opening).decompress() else {
        return false;
    };
    if low_commitment - low_opening != RISTRETTO_BASEPOINT_POINT * Scalar::from(witness.low_total)
        || high_commitment - high_opening
            != RISTRETTO_BASEPOINT_POINT * Scalar::from(witness.high_total)
    {
        return false;
    }

    let Some(high_amount) = witness.high_total.checked_shl(16) else {
        return false;
    };
    witness
        .low_total
        .checked_add(high_amount)
        .is_some_and(|amount| amount == statement.total_bid_amount)
}

fn valid_accepted_entries(statement: &AggregateDecryptionStatement, count: usize) -> bool {
    for index in 0..MAX_FUNDED_BIDS {
        let commitment = statement.funded_bid_commitments[index];
        let context_hash = statement.accepted_transfer_context_hashes[index];
        if index < count {
            if commitment == [0; 32]
                || context_hash == [0; 32]
                || statement.funded_bid_commitments[..index].contains(&commitment)
                || statement.accepted_transfer_context_hashes[..index].contains(&context_hash)
            {
                return false;
            }
        } else if commitment != [0; 32] || context_hash != [0; 32] {
            return false;
        }
    }
    true
}

fn decompress_ciphertext(ciphertext: &[u8; 64]) -> Option<(RistrettoPoint, [u8; 32])> {
    let commitment_bytes: [u8; 32] = ciphertext[..32].try_into().ok()?;
    let handle_bytes: [u8; 32] = ciphertext[32..].try_into().ok()?;
    let commitment = CompressedRistretto(commitment_bytes).decompress()?;
    CompressedRistretto(handle_bytes).decompress()?;
    Some((commitment, handle_bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        verify_aggregate_decryption_relation, verify_trustee_key_setup_relation,
        AggregateDecryptionStatement, AggregateDecryptionWitness, TrusteeKeySetupStatement,
        TRUSTEE_KEY_SETUP_PUBLIC_VALUES_LEN,
    };
    use crate::{
        add_elgamal_ciphertexts, funded_bid_merkle_root,
        threshold::{
            aggregate_decryption_context_hash, apply_decryption_factor, apply_inverse_key_factor,
            key_transform_context_hash, prove_dleq_with_nonce, solana_pedersen_h,
            AggregateComponent, TrusteeDecryptionStep, TrusteeKeyTransformStep, TRUSTEE_COUNT,
        },
        MAX_FUNDED_BIDS,
    };
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT,
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    };

    const PROGRAM_ID: [u8; 32] = [1; 32];
    const POOL: [u8; 32] = [2; 32];
    const AUCTION_ID: [u8; 32] = [3; 32];
    const FUNDING_MINT: [u8; 32] = [4; 32];
    const CONFIDENTIAL_VAULT: [u8; 32] = [5; 32];
    const KEY_EPOCH: [u8; 32] = [6; 32];
    const TRUSTEE_IDS: [[u8; 32]; TRUSTEE_COUNT] = [[7; 32], [8; 32], [9; 32]];
    const FACTORS: [u64; TRUSTEE_COUNT] = [13, 17, 19];

    fn point(bytes: &[u8; 32]) -> RistrettoPoint {
        CompressedRistretto(*bytes).decompress().unwrap()
    }

    fn encrypt(pubkey: &RistrettoPoint, amount: u64, opening: Scalar) -> [u8; 64] {
        let h = point(&solana_pedersen_h());
        let commitment = (RISTRETTO_BASEPOINT_POINT * Scalar::from(amount) + h * opening)
            .compress()
            .to_bytes();
        let handle = (pubkey * opening).compress().to_bytes();
        let mut ciphertext = [0; 64];
        ciphertext[..32].copy_from_slice(&commitment);
        ciphertext[32..].copy_from_slice(&handle);
        ciphertext
    }

    fn fixture() -> (AggregateDecryptionStatement, AggregateDecryptionWitness) {
        let factors = FACTORS.map(Scalar::from);
        let verification_shares =
            factors.map(|factor| (RISTRETTO_BASEPOINT_POINT * factor).compress().to_bytes());
        let combined_factor = factors.iter().copied().product::<Scalar>();
        let auditor_key = point(&solana_pedersen_h()) * combined_factor.invert();

        let bid_amounts = [100_000u64, 200_000u64];
        let low_openings = [Scalar::from(23u64), Scalar::from(29u64)];
        let high_openings = [Scalar::from(31u64), Scalar::from(37u64)];
        let low_ciphertexts = [
            encrypt(&auditor_key, bid_amounts[0] & 0xffff, low_openings[0]),
            encrypt(&auditor_key, bid_amounts[1] & 0xffff, low_openings[1]),
        ];
        let high_ciphertexts = [
            encrypt(&auditor_key, bid_amounts[0] >> 16, high_openings[0]),
            encrypt(&auditor_key, bid_amounts[1] >> 16, high_openings[1]),
        ];
        let aggregate_ciphertext_low =
            add_elgamal_ciphertexts(&low_ciphertexts[0], &low_ciphertexts[1]).unwrap();
        let aggregate_ciphertext_high =
            add_elgamal_ciphertexts(&high_ciphertexts[0], &high_ciphertexts[1]).unwrap();

        let mut funded_bid_commitments = [[0; 32]; MAX_FUNDED_BIDS];
        funded_bid_commitments[0] = [10; 32];
        funded_bid_commitments[1] = [11; 32];
        let mut accepted_transfer_context_hashes = [[0; 32]; MAX_FUNDED_BIDS];
        accepted_transfer_context_hashes[0] = [12; 32];
        accepted_transfer_context_hashes[1] = [14; 32];
        let statement = AggregateDecryptionStatement {
            program_id: PROGRAM_ID,
            pool_account: POOL,
            auction_id: AUCTION_ID,
            funded_bid_root: funded_bid_merkle_root(&funded_bid_commitments),
            funding_mint: FUNDING_MINT,
            confidential_vault: CONFIDENTIAL_VAULT,
            auditor_pubkey: auditor_key.compress().to_bytes(),
            key_epoch: KEY_EPOCH,
            trustee_ids: TRUSTEE_IDS,
            verification_shares,
            funded_bid_count: 2,
            funded_bid_commitments,
            accepted_transfer_context_hashes,
            aggregate_ciphertext_low,
            aggregate_ciphertext_high,
            total_bid_amount: bid_amounts.iter().sum(),
        };
        let digest = statement.finalized_aggregate_digest();

        let key_nonces = [
            Scalar::from(41u64),
            Scalar::from(43u64),
            Scalar::from(47u64),
        ];
        let mut current_key = solana_pedersen_h();
        let key_setup_steps = core::array::from_fn(|index| {
            let trustee_index = u8::try_from(index + 1).unwrap();
            let previous_key = current_key;
            current_key = apply_inverse_key_factor(&current_key, &factors[index]).unwrap();
            let context_hash = key_transform_context_hash(
                &PROGRAM_ID,
                &FUNDING_MINT,
                &KEY_EPOCH,
                &TRUSTEE_IDS[index],
                trustee_index,
            )
            .unwrap();
            let (_, proof) = prove_dleq_with_nonce(
                &factors[index],
                &key_nonces[index],
                context_hash,
                current_key,
                previous_key,
            )
            .unwrap();
            TrusteeKeyTransformStep {
                trustee_id: TRUSTEE_IDS[index],
                derived_public_key: current_key,
                proof,
            }
        });

        let make_steps = |ciphertext: &[u8; 64],
                          component: AggregateComponent,
                          nonces: [Scalar; TRUSTEE_COUNT]| {
            let mut current_handle: [u8; 32] = ciphertext[32..].try_into().unwrap();
            core::array::from_fn(|index| {
                let trustee_index = u8::try_from(index + 1).unwrap();
                let input = current_handle;
                current_handle = apply_decryption_factor(&input, &factors[index]).unwrap();
                let context_hash = aggregate_decryption_context_hash(
                    &PROGRAM_ID,
                    &POOL,
                    &digest,
                    &KEY_EPOCH,
                    &TRUSTEE_IDS[index],
                    trustee_index,
                    component,
                )
                .unwrap();
                let (_, proof) = prove_dleq_with_nonce(
                    &factors[index],
                    &nonces[index],
                    context_hash,
                    input,
                    current_handle,
                )
                .unwrap();
                TrusteeDecryptionStep {
                    trustee_id: TRUSTEE_IDS[index],
                    output_point: current_handle,
                    proof,
                }
            })
        };

        let witness = AggregateDecryptionWitness {
            key_setup_steps,
            low_steps: make_steps(
                &aggregate_ciphertext_low,
                AggregateComponent::Low,
                [
                    Scalar::from(53u64),
                    Scalar::from(59u64),
                    Scalar::from(61u64),
                ],
            ),
            high_steps: make_steps(
                &aggregate_ciphertext_high,
                AggregateComponent::High,
                [
                    Scalar::from(67u64),
                    Scalar::from(71u64),
                    Scalar::from(73u64),
                ],
            ),
            low_total: bid_amounts.iter().map(|amount| amount & 0xffff).sum(),
            high_total: bid_amounts.iter().map(|amount| amount >> 16).sum(),
        };
        (statement, witness)
    }

    #[test]
    fn accepted_set_and_both_aggregate_transcripts_prove_the_total() {
        let (statement, witness) = fixture();
        assert!(verify_aggregate_decryption_relation(&statement, &witness));
        let key_setup = TrusteeKeySetupStatement {
            program_id: statement.program_id,
            funding_mint: statement.funding_mint,
            auditor_pubkey: statement.auditor_pubkey,
            key_epoch: statement.key_epoch,
            trustee_ids: statement.trustee_ids,
            verification_shares: statement.verification_shares,
        };
        assert!(verify_trustee_key_setup_relation(
            &key_setup,
            &witness.key_setup_steps
        ));
        let mut changed_key_setup = key_setup;
        changed_key_setup.key_epoch[0] ^= 1;
        assert!(!verify_trustee_key_setup_relation(
            &changed_key_setup,
            &witness.key_setup_steps
        ));
        assert_eq!(
            key_setup.public_values().len(),
            TRUSTEE_KEY_SETUP_PUBLIC_VALUES_LEN
        );
        assert_ne!(key_setup.public_values(), changed_key_setup.public_values());
        let public_values = statement.public_values();
        assert_eq!(&public_values[..32], &PROGRAM_ID);
        assert_eq!(&public_values[32..64], &POOL);
        assert_eq!(
            &public_values[64..96],
            &statement.finalized_aggregate_digest()
        );
        assert_eq!(
            u64::from_le_bytes(public_values[96..104].try_into().unwrap()),
            300_000
        );
    }

    #[test]
    fn total_mutation_and_omitted_or_replayed_entries_are_rejected() {
        let (statement, witness) = fixture();
        let mut changed = statement;
        changed.total_bid_amount += 1;
        assert!(!verify_aggregate_decryption_relation(&changed, &witness));

        let mut changed = statement;
        changed.funded_bid_count = 1;
        assert!(!verify_aggregate_decryption_relation(&changed, &witness));

        let mut changed = statement;
        changed.accepted_transfer_context_hashes[1] = changed.accepted_transfer_context_hashes[0];
        assert!(!verify_aggregate_decryption_relation(&changed, &witness));

        let mut changed = statement;
        changed.funded_bid_commitments[2] = [15; 32];
        assert!(!verify_aggregate_decryption_relation(&changed, &witness));
    }

    #[test]
    fn wrong_component_proof_or_out_of_range_limb_is_rejected() {
        let (statement, witness) = fixture();
        let mut changed = witness;
        changed.high_steps[0] = changed.low_steps[0];
        assert!(!verify_aggregate_decryption_relation(&statement, &changed));

        let mut changed = witness;
        changed.low_total = 2 * u64::from(u16::MAX) + 1;
        assert!(!verify_aggregate_decryption_relation(&statement, &changed));
    }
}
