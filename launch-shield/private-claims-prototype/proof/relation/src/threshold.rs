//! Three-of-three verifiable scalar transforms for Token-2022 auditor ElGamal.
//!
//! Each trustee holds an independent, nonzero scalar factor. The public auditor
//! key is derived by applying each factor's inverse to Solana's Pedersen H
//! generator. Decryption applies all three factors to an aggregate handle.
//! This module provides the point operations and DLEQ relations; it does not
//! implement trustee identity, durable key custody, authenticated transport,
//! or a production key ceremony.

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha2::{Digest, Sha256};
use sha3::Sha3_512;

pub const TRUSTEE_COUNT: usize = 3;

const DLEQ_PROOF_DOMAIN: &[u8] = b"launch-shield:private-claims:3-of-3:dleq:v1";
const KEY_TRANSFORM_CONTEXT_DOMAIN: &[u8] = b"launch-shield:private-claims:3-of-3:key-transform:v1";
const AGGREGATE_DECRYPTION_CONTEXT_DOMAIN: &[u8] =
    b"launch-shield:private-claims:3-of-3:aggregate-decryption:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateComponent {
    Low,
    High,
}

impl AggregateComponent {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Low => b"low",
            Self::High => b"high",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DleqStatement {
    /// Digest binding the proof to one key-setup or finalized-aggregate step.
    pub context_hash: [u8; 32],
    /// Trustee verification key, `secret_share * G`.
    pub public_share: [u8; 32],
    /// Point multiplied by the trustee share.
    pub input_point: [u8; 32],
    /// Resulting point, `secret_share * input_point`.
    pub output_point: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DleqProof {
    pub commitment_base: [u8; 32],
    pub commitment_input: [u8; 32],
    pub response: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrusteeKeyTransformStep {
    pub trustee_id: [u8; 32],
    /// Public key after applying this trustee's inverse factor.
    pub derived_public_key: [u8; 32],
    pub proof: DleqProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrusteeDecryptionStep {
    pub trustee_id: [u8; 32],
    /// Decryption handle after applying this trustee's factor.
    pub output_point: [u8; 32],
    pub proof: DleqProof,
}

pub fn key_transform_context_hash(
    program_id: &[u8; 32],
    funding_mint: &[u8; 32],
    key_epoch: &[u8; 32],
    trustee_id: &[u8; 32],
    trustee_index: u8,
) -> Option<[u8; 32]> {
    if !valid_context_keys(&[*program_id, *funding_mint, *key_epoch, *trustee_id])
        || !(1..=u8::try_from(TRUSTEE_COUNT).ok()?).contains(&trustee_index)
    {
        return None;
    }

    Some(hash_domain(
        KEY_TRANSFORM_CONTEXT_DOMAIN,
        &[
            program_id,
            funding_mint,
            key_epoch,
            trustee_id,
            &[trustee_index],
        ],
    ))
}

pub fn aggregate_decryption_context_hash(
    program_id: &[u8; 32],
    pool_account: &[u8; 32],
    finalized_aggregate_digest: &[u8; 32],
    key_epoch: &[u8; 32],
    trustee_id: &[u8; 32],
    trustee_index: u8,
    component: AggregateComponent,
) -> Option<[u8; 32]> {
    if !valid_context_keys(&[
        *program_id,
        *pool_account,
        *finalized_aggregate_digest,
        *key_epoch,
        *trustee_id,
    ]) || !(1..=u8::try_from(TRUSTEE_COUNT).ok()?).contains(&trustee_index)
    {
        return None;
    }

    Some(hash_domain(
        AGGREGATE_DECRYPTION_CONTEXT_DOMAIN,
        &[
            program_id,
            pool_account,
            finalized_aggregate_digest,
            key_epoch,
            trustee_id,
            &[trustee_index],
            component.tag(),
        ],
    ))
}

/// Verify the fixed trustee order and all three public-key inverse transforms.
pub fn verify_three_of_three_key_transcript(
    program_id: &[u8; 32],
    funding_mint: &[u8; 32],
    key_epoch: &[u8; 32],
    trustee_ids: &[[u8; 32]; TRUSTEE_COUNT],
    verification_shares: &[[u8; 32]; TRUSTEE_COUNT],
    steps: &[TrusteeKeyTransformStep; TRUSTEE_COUNT],
) -> Option<[u8; 32]> {
    if !valid_trustee_registry(trustee_ids, verification_shares) {
        return None;
    }

    let mut current_public_key = solana_pedersen_h();
    for (index, step) in steps.iter().enumerate() {
        let trustee_index = u8::try_from(index + 1).ok()?;
        if step.trustee_id != trustee_ids[index] {
            return None;
        }
        let context_hash = key_transform_context_hash(
            program_id,
            funding_mint,
            key_epoch,
            &step.trustee_id,
            trustee_index,
        )?;
        let statement = DleqStatement {
            context_hash,
            public_share: verification_shares[index],
            input_point: step.derived_public_key,
            output_point: current_public_key,
        };
        if !verify_dleq(&statement, &step.proof) {
            return None;
        }
        current_public_key = step.derived_public_key;
    }

    Some(current_public_key)
}

/// Verify all three ordered decryption transforms for one finalized aggregate component.
pub fn verify_three_of_three_decryption_transcript(
    program_id: &[u8; 32],
    pool_account: &[u8; 32],
    finalized_aggregate_digest: &[u8; 32],
    key_epoch: &[u8; 32],
    trustee_ids: &[[u8; 32]; TRUSTEE_COUNT],
    verification_shares: &[[u8; 32]; TRUSTEE_COUNT],
    component: AggregateComponent,
    aggregate_handle: &[u8; 32],
    steps: &[TrusteeDecryptionStep; TRUSTEE_COUNT],
) -> Option<[u8; 32]> {
    if !valid_trustee_registry(trustee_ids, verification_shares) {
        return None;
    }
    decompress(aggregate_handle)?;

    let mut current_handle = *aggregate_handle;
    for (index, step) in steps.iter().enumerate() {
        let trustee_index = u8::try_from(index + 1).ok()?;
        if step.trustee_id != trustee_ids[index] {
            return None;
        }
        let context_hash = aggregate_decryption_context_hash(
            program_id,
            pool_account,
            finalized_aggregate_digest,
            key_epoch,
            &step.trustee_id,
            trustee_index,
            component,
        )?;
        let statement = DleqStatement {
            context_hash,
            public_share: verification_shares[index],
            input_point: current_handle,
            output_point: step.output_point,
        };
        if !verify_dleq(&statement, &step.proof) {
            return None;
        }
        current_handle = step.output_point;
    }

    Some(current_handle)
}

/// Solana ZK SDK's Pedersen H generator used by Token-2022 ElGamal ciphertexts.
pub fn solana_pedersen_h() -> [u8; 32] {
    RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes())
        .compress()
        .to_bytes()
}

/// Derive the next public-key point by applying one trustee factor's inverse.
pub fn apply_inverse_key_factor(
    current_public_key: &[u8; 32],
    secret_share: &Scalar,
) -> Option<[u8; 32]> {
    if *secret_share == Scalar::ZERO {
        return None;
    }
    let current = decompress(current_public_key)?;
    Some((current * secret_share.invert()).compress().to_bytes())
}

/// Apply one trustee factor to a decryption handle.
pub fn apply_decryption_factor(
    current_handle: &[u8; 32],
    secret_share: &Scalar,
) -> Option<[u8; 32]> {
    if *secret_share == Scalar::ZERO {
        return None;
    }
    Some(
        (decompress(current_handle)? * secret_share)
            .compress()
            .to_bytes(),
    )
}

/// Prove `output_point = secret_share * input_point` with a Chaum-Pedersen DLEQ.
///
/// `nonce` must be fresh and unpredictable for every proof. Reusing it for the
/// same trustee share across statements can reveal the share.
pub fn prove_dleq_with_nonce(
    secret_share: &Scalar,
    nonce: &Scalar,
    context_hash: [u8; 32],
    input_point: [u8; 32],
    output_point: [u8; 32],
) -> Option<(DleqStatement, DleqProof)> {
    if *secret_share == Scalar::ZERO || *nonce == Scalar::ZERO {
        return None;
    }
    let input = decompress(&input_point)?;
    let output = decompress(&output_point)?;
    let public_share = RISTRETTO_BASEPOINT_POINT * secret_share;
    if public_share == RistrettoPoint::identity() || input * secret_share != output {
        return None;
    }

    let statement = DleqStatement {
        context_hash,
        public_share: public_share.compress().to_bytes(),
        input_point,
        output_point,
    };
    let commitment_base = (RISTRETTO_BASEPOINT_POINT * nonce).compress().to_bytes();
    let commitment_input = (input * nonce).compress().to_bytes();
    let proof = DleqProof {
        commitment_base,
        commitment_input,
        response: (nonce
            + dleq_challenge(&statement, &commitment_base, &commitment_input) * secret_share)
            .to_bytes(),
    };

    Some((statement, proof))
}

/// Verify the proof and reject malformed points or non-canonical responses.
pub fn verify_dleq(statement: &DleqStatement, proof: &DleqProof) -> bool {
    let Some(public_share) = decompress(&statement.public_share) else {
        return false;
    };
    let Some(input) = decompress(&statement.input_point) else {
        return false;
    };
    let Some(output) = decompress(&statement.output_point) else {
        return false;
    };
    let Some(commitment_base) = decompress(&proof.commitment_base) else {
        return false;
    };
    let Some(commitment_input) = decompress(&proof.commitment_input) else {
        return false;
    };
    let Some(response) = Scalar::from_canonical_bytes(proof.response).into_option() else {
        return false;
    };
    if public_share == RistrettoPoint::identity() {
        return false;
    }

    let challenge = dleq_challenge(statement, &proof.commitment_base, &proof.commitment_input);
    RISTRETTO_BASEPOINT_POINT * response == commitment_base + public_share * challenge
        && input * response == commitment_input + output * challenge
}

fn dleq_challenge(
    statement: &DleqStatement,
    commitment_base: &[u8; 32],
    commitment_input: &[u8; 32],
) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(DLEQ_PROOF_DOMAIN);
    hasher.update(statement.context_hash);
    hasher.update(statement.public_share);
    hasher.update(statement.input_point);
    hasher.update(statement.output_point);
    hasher.update(commitment_base);
    hasher.update(commitment_input);
    let wide: [u8; 64] = hasher.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn decompress(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn hash_domain(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn valid_context_keys(keys: &[[u8; 32]]) -> bool {
    keys.iter().all(|key| *key != [0; 32])
}

fn valid_trustee_registry(
    trustee_ids: &[[u8; 32]; TRUSTEE_COUNT],
    verification_shares: &[[u8; 32]; TRUSTEE_COUNT],
) -> bool {
    for index in 0..TRUSTEE_COUNT {
        if trustee_ids[index] == [0; 32]
            || trustee_ids[..index].contains(&trustee_ids[index])
            || verification_shares[..index].contains(&verification_shares[index])
            || decompress(&verification_shares[index])
                .is_none_or(|share| share == RistrettoPoint::identity())
        {
            return false;
        }
    }
    true
}

pub fn is_valid_trustee_registry(
    trustee_ids: &[[u8; 32]; TRUSTEE_COUNT],
    verification_shares: &[[u8; 32]; TRUSTEE_COUNT],
) -> bool {
    valid_trustee_registry(trustee_ids, verification_shares)
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_decryption_context_hash, apply_decryption_factor, apply_inverse_key_factor,
        key_transform_context_hash, prove_dleq_with_nonce, solana_pedersen_h,
        valid_trustee_registry, verify_dleq, verify_three_of_three_decryption_transcript,
        verify_three_of_three_key_transcript, AggregateComponent, TrusteeDecryptionStep,
        TrusteeKeyTransformStep, TRUSTEE_COUNT,
    };
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar,
    };

    const PROGRAM_ID: [u8; 32] = [1; 32];
    const FUNDING_MINT: [u8; 32] = [2; 32];
    const POOL: [u8; 32] = [3; 32];
    const AGGREGATE_DIGEST: [u8; 32] = [4; 32];
    const KEY_EPOCH: [u8; 32] = [5; 32];
    const TRUSTEE_IDS: [[u8; 32]; TRUSTEE_COUNT] = [[6; 32], [7; 32], [8; 32]];

    fn point(bytes: &[u8; 32]) -> curve25519_dalek::ristretto::RistrettoPoint {
        CompressedRistretto(*bytes).decompress().unwrap()
    }

    #[test]
    fn three_trustees_prove_key_setup_and_aggregate_decryption_steps() {
        let factors = [Scalar::from(3u64), Scalar::from(5u64), Scalar::from(7u64)];
        let nonces = [
            Scalar::from(11u64),
            Scalar::from(13u64),
            Scalar::from(17u64),
        ];
        let decryption_nonces = [
            Scalar::from(19u64),
            Scalar::from(23u64),
            Scalar::from(29u64),
        ];
        let verification_shares =
            factors.map(|factor| (RISTRETTO_BASEPOINT_POINT * factor).compress().to_bytes());
        let h = point(&solana_pedersen_h());
        let mut current_public_key = h.compress().to_bytes();
        let key_steps = core::array::from_fn(|index| {
            let trustee_index = u8::try_from(index + 1).unwrap();
            let context = key_transform_context_hash(
                &PROGRAM_ID,
                &FUNDING_MINT,
                &KEY_EPOCH,
                &TRUSTEE_IDS[index],
                trustee_index,
            )
            .unwrap();
            let previous_key = current_public_key;
            current_public_key =
                apply_inverse_key_factor(&current_public_key, &factors[index]).unwrap();
            let (_, proof) = prove_dleq_with_nonce(
                &factors[index],
                &nonces[index],
                context,
                current_public_key,
                previous_key,
            )
            .unwrap();
            TrusteeKeyTransformStep {
                trustee_id: TRUSTEE_IDS[index],
                derived_public_key: current_public_key,
                proof,
            }
        });
        let public_key = verify_three_of_three_key_transcript(
            &PROGRAM_ID,
            &FUNDING_MINT,
            &KEY_EPOCH,
            &TRUSTEE_IDS,
            &verification_shares,
            &key_steps,
        )
        .unwrap();
        assert_eq!(current_public_key, public_key);

        let total_secret = factors.iter().copied().product::<Scalar>();
        assert_eq!(point(&public_key), h * total_secret.invert());

        let amount = 987_654u64;
        let opening = Scalar::from(123_457u64);
        let commitment = RISTRETTO_BASEPOINT_POINT * Scalar::from(amount) + h * opening;
        let mut current_handle = point(&public_key) * opening;
        let aggregate_handle = current_handle.compress().to_bytes();
        let decryption_steps = core::array::from_fn(|index| {
            let trustee_index = u8::try_from(index + 1).unwrap();
            let context = aggregate_decryption_context_hash(
                &PROGRAM_ID,
                &POOL,
                &AGGREGATE_DIGEST,
                &KEY_EPOCH,
                &TRUSTEE_IDS[index],
                trustee_index,
                AggregateComponent::Low,
            )
            .unwrap();
            let input = current_handle.compress().to_bytes();
            let output = apply_decryption_factor(&input, &factors[index]).unwrap();
            let (_, proof) = prove_dleq_with_nonce(
                &factors[index],
                &decryption_nonces[index],
                context,
                input,
                output,
            )
            .unwrap();
            current_handle = point(&output);
            TrusteeDecryptionStep {
                trustee_id: TRUSTEE_IDS[index],
                output_point: output,
                proof,
            }
        });
        let decrypted_handle = verify_three_of_three_decryption_transcript(
            &PROGRAM_ID,
            &POOL,
            &AGGREGATE_DIGEST,
            &KEY_EPOCH,
            &TRUSTEE_IDS,
            &verification_shares,
            AggregateComponent::Low,
            &aggregate_handle,
            &decryption_steps,
        )
        .unwrap();
        assert_eq!(current_handle.compress().to_bytes(), decrypted_handle);
        assert_eq!(
            commitment - point(&decrypted_handle),
            RISTRETTO_BASEPOINT_POINT * Scalar::from(amount)
        );

        let mut missing_trustee = decryption_steps;
        missing_trustee[2].trustee_id = [0; 32];
        assert!(verify_three_of_three_decryption_transcript(
            &PROGRAM_ID,
            &POOL,
            &AGGREGATE_DIGEST,
            &KEY_EPOCH,
            &TRUSTEE_IDS,
            &verification_shares,
            AggregateComponent::Low,
            &aggregate_handle,
            &missing_trustee,
        )
        .is_none());
    }

    #[test]
    fn fewer_than_three_factors_do_not_complete_decryption() {
        let factors = [Scalar::from(3u64), Scalar::from(5u64), Scalar::from(7u64)];
        let h = point(&solana_pedersen_h());
        let total_secret = factors.iter().copied().product::<Scalar>();
        let public_key = h * total_secret.invert();
        let opening = Scalar::from(19u64);
        let initial_handle = public_key * opening;
        let after_two = initial_handle * factors[0] * factors[1];

        assert_ne!(after_two, h * opening);
    }

    #[test]
    fn proofs_are_bound_to_pool_epoch_trustee_and_component() {
        let secret = Scalar::from(17u64);
        let nonce = Scalar::from(23u64);
        let input = (RISTRETTO_BASEPOINT_POINT * Scalar::from(31u64))
            .compress()
            .to_bytes();
        let output = (point(&input) * secret).compress().to_bytes();
        let context = aggregate_decryption_context_hash(
            &PROGRAM_ID,
            &POOL,
            &AGGREGATE_DIGEST,
            &KEY_EPOCH,
            &TRUSTEE_IDS[0],
            1,
            AggregateComponent::Low,
        )
        .unwrap();
        let (statement, proof) =
            prove_dleq_with_nonce(&secret, &nonce, context, input, output).unwrap();

        assert!(verify_dleq(&statement, &proof));
        let wrong_component = aggregate_decryption_context_hash(
            &PROGRAM_ID,
            &POOL,
            &AGGREGATE_DIGEST,
            &KEY_EPOCH,
            &TRUSTEE_IDS[0],
            1,
            AggregateComponent::High,
        )
        .unwrap();
        let wrong_epoch = aggregate_decryption_context_hash(
            &PROGRAM_ID,
            &POOL,
            &AGGREGATE_DIGEST,
            &[9; 32],
            &TRUSTEE_IDS[0],
            1,
            AggregateComponent::Low,
        )
        .unwrap();
        let mut changed = statement;
        changed.context_hash = wrong_component;
        assert!(!verify_dleq(&changed, &proof));
        changed.context_hash = wrong_epoch;
        assert!(!verify_dleq(&changed, &proof));
    }

    #[test]
    fn malformed_points_zero_factors_and_invalid_trustees_are_rejected() {
        let zero = Scalar::ZERO;
        assert!(apply_inverse_key_factor(&[u8::MAX; 32], &Scalar::ONE).is_none());
        assert!(apply_inverse_key_factor(&[1; 32], &zero).is_none());
        assert!(key_transform_context_hash(
            &PROGRAM_ID,
            &FUNDING_MINT,
            &KEY_EPOCH,
            &TRUSTEE_IDS[0],
            0,
        )
        .is_none());
        assert!(aggregate_decryption_context_hash(
            &PROGRAM_ID,
            &POOL,
            &[0; 32],
            &KEY_EPOCH,
            &TRUSTEE_IDS[0],
            1,
            AggregateComponent::Low,
        )
        .is_none());

        let repeated_verification_share = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        let duplicate_shares = [
            repeated_verification_share,
            repeated_verification_share,
            (RISTRETTO_BASEPOINT_POINT * Scalar::from(3u64))
                .compress()
                .to_bytes(),
        ];
        assert!(!valid_trustee_registry(&TRUSTEE_IDS, &duplicate_shares));
    }
}
