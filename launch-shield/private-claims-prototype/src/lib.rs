#![cfg(test)]

//! Host-only arithmetic feasibility tests for Token-2022's `H/s` key mapping.
//!
//! This crate centrally simulates all trustee shares in one process. It is not
//! a DKG, MPC implementation, malicious-secure protocol, or production API.

use curve25519_dalek::scalar::Scalar;
use solana_zk_sdk::encryption::{
    elgamal::{ElGamalPubkey, ElGamalSecretKey},
    pedersen::{G, H},
    pod::elgamal::PodElGamalPubkey,
};

mod claim;
mod funding;
mod vss;

const INDICES: [u64; 3] = [1, 2, 3];

fn evaluate_degree_one(secret: Scalar, slope: Scalar, index: u64) -> Scalar {
    secret + slope * Scalar::from(index)
}

fn inverse_of_nonzero(value: Scalar) -> Option<Scalar> {
    (value != Scalar::ZERO).then(|| value.invert())
}

#[test]
fn centrally_simulated_masked_inversion_matches_sdk_key_and_decryption() {
    // Public test fixtures only. No scalar from this test is secret or usable
    // as a production key.
    let secret = Scalar::from(123_456_789u64);
    let secret_slope = Scalar::from(987_654_321u64);
    let mask = Scalar::from(456_789_123u64);
    let mask_slope = Scalar::from(321_987_654u64);

    let secret_shares = INDICES.map(|index| evaluate_degree_one(secret, secret_slope, index));
    let mask_shares = INDICES.map(|index| evaluate_degree_one(mask, mask_slope, index));

    // For shares at x=1,2,3, these interpolate a degree-two product at x=0.
    let interpolation_weights = [Scalar::from(3u64), -Scalar::from(3u64), Scalar::ONE];

    // A centralized simulation of degree reduction: each dealer reshapes its
    // weighted local product as a degree-one polynomial, then each recipient
    // sums the received evaluations.
    let degree_reduction_slopes = [
        Scalar::from(17u64),
        Scalar::from(23u64),
        Scalar::from(41u64),
    ];
    let masked_product_shares = INDICES.map(|recipient_index| {
        (0..INDICES.len())
            .map(|dealer| {
                let weighted_product =
                    interpolation_weights[dealer] * secret_shares[dealer] * mask_shares[dealer];
                weighted_product + degree_reduction_slopes[dealer] * Scalar::from(recipient_index)
            })
            .sum::<Scalar>()
    });

    // Open z = s*r from the first two evaluations of its degree-one sharing.
    let masked_product = Scalar::from(2u64) * masked_product_shares[0] - masked_product_shares[1];
    assert_eq!(masked_product, secret * mask);
    let inverse = inverse_of_nonzero(masked_product).expect("nonzero mask product");

    // Scaling the mask shares by 1/z yields shares of 1/s. Interpolating their
    // public points produces H/s, the mapping used by the Solana SDK.
    let inverse_shares = mask_shares.map(|share| share * inverse);
    let inverse_public_share_1 = *H * inverse_shares[0];
    let inverse_public_share_2 = *H * inverse_shares[1];
    let derived_public_key_point =
        inverse_public_share_1 * Scalar::from(2u64) - inverse_public_share_2;

    let sdk_public_key = ElGamalPubkey::new(&ElGamalSecretKey::from(secret));
    assert_eq!(derived_public_key_point, *sdk_public_key.get_point());
    let pod_key: PodElGamalPubkey = sdk_public_key.into();
    assert!(ElGamalPubkey::try_from(pod_key).is_ok());

    // The original shares of s, not the inverse shares, remain the decryption
    // shares for this SDK key.
    let decryption_key = ElGamalPubkey::new(&ElGamalSecretKey::from(secret));
    let ciphertext = decryption_key.encrypt_u64(987_654);
    let handle = ciphertext.handle.get_point();
    let partial_1 = handle * secret_shares[0];
    let partial_2 = handle * secret_shares[1];
    let combined = partial_1 * Scalar::from(2u64) - partial_2;
    let plaintext_point = ciphertext.commitment.get_point() - combined;
    assert_eq!(plaintext_point, *G * Scalar::from(987_654u64));
}

#[test]
fn two_share_interpolation_does_not_recover_a_degree_two_product() {
    let secret = Scalar::from(123_456_789u64);
    let secret_slope = Scalar::from(987_654_321u64);
    let mask = Scalar::from(456_789_123u64);
    let mask_slope = Scalar::from(321_987_654u64);

    let local_products = INDICES.map(|index| {
        evaluate_degree_one(secret, secret_slope, index)
            * evaluate_degree_one(mask, mask_slope, index)
    });

    let two_share_guess = Scalar::from(2u64) * local_products[0] - local_products[1];
    assert_ne!(two_share_guess, secret * mask);

    let three_share_product = Scalar::from(3u64) * local_products[0]
        - Scalar::from(3u64) * local_products[1]
        + local_products[2];
    assert_eq!(three_share_product, secret * mask);
}

#[test]
fn zero_masked_product_is_rejected_before_inversion() {
    assert_eq!(inverse_of_nonzero(Scalar::ZERO), None);
    assert_eq!(
        inverse_of_nonzero(Scalar::from(7u64)),
        Some(Scalar::from(7u64).invert())
    );
}

#[test]
fn interpolating_public_keys_of_shares_does_not_match_the_sdk_key() {
    let secret = Scalar::from(123_456_789u64);
    let slope = Scalar::from(987_654_321u64);
    let share_1 = evaluate_degree_one(secret, slope, 1);
    let share_2 = evaluate_degree_one(secret, slope, 2);

    let share_1_key = ElGamalPubkey::new(&ElGamalSecretKey::from(share_1));
    let share_2_key = ElGamalPubkey::new(&ElGamalSecretKey::from(share_2));
    let naive_interpolation =
        *share_1_key.get_point() * Scalar::from(2u64) - *share_2_key.get_point();
    let sdk_key = ElGamalPubkey::new(&ElGamalSecretKey::from(secret));

    assert_ne!(naive_interpolation, *sdk_key.get_point());
}

#[test]
fn three_of_three_transforms_match_the_pinned_sdk_key_and_ciphertexts() {
    use private_claims_proof_relation::threshold::{
        aggregate_decryption_context_hash, apply_decryption_factor, apply_inverse_key_factor,
        key_transform_context_hash, prove_dleq_with_nonce, solana_pedersen_h, verify_dleq,
        AggregateComponent,
    };

    const PROGRAM_ID: [u8; 32] = [11; 32];
    const FUNDING_MINT: [u8; 32] = [12; 32];
    const POOL: [u8; 32] = [13; 32];
    const AGGREGATE_DIGEST: [u8; 32] = [14; 32];
    const KEY_EPOCH: [u8; 32] = [15; 32];
    const TRUSTEE_IDS: [[u8; 32]; 3] = [[16; 32], [17; 32], [18; 32]];

    let shares = [
        Scalar::from(31u64),
        Scalar::from(37u64),
        Scalar::from(41u64),
    ];
    let nonces = [
        Scalar::from(43u64),
        Scalar::from(47u64),
        Scalar::from(53u64),
    ];
    let decryption_nonces = [
        Scalar::from(59u64),
        Scalar::from(61u64),
        Scalar::from(67u64),
    ];
    let mut public_key = solana_pedersen_h();

    for index in 0..shares.len() {
        let trustee_index = u8::try_from(index + 1).unwrap();
        let context = key_transform_context_hash(
            &PROGRAM_ID,
            &FUNDING_MINT,
            &KEY_EPOCH,
            &TRUSTEE_IDS[index],
            trustee_index,
        )
        .unwrap();
        let previous_key = public_key;
        public_key = apply_inverse_key_factor(&public_key, &shares[index]).unwrap();
        let (statement, proof) = prove_dleq_with_nonce(
            &shares[index],
            &nonces[index],
            context,
            public_key,
            previous_key,
        )
        .unwrap();
        assert!(verify_dleq(&statement, &proof));
    }

    let total_secret = shares.iter().copied().product::<Scalar>();
    let sdk_key = ElGamalPubkey::new(&ElGamalSecretKey::from(total_secret));
    assert_eq!(public_key, sdk_key.get_point().compress().to_bytes());
    assert_eq!(*H, *sdk_key.get_point() * total_secret);

    let ciphertexts = [sdk_key.encrypt_u64(987_654), sdk_key.encrypt_u64(123_456)];
    let mut aggregate_commitment = curve25519_dalek::ristretto::RistrettoPoint::default();
    let mut aggregate_handle = curve25519_dalek::ristretto::RistrettoPoint::default();
    for ciphertext in &ciphertexts {
        aggregate_commitment += ciphertext.commitment.get_point();
        aggregate_handle += ciphertext.handle.get_point();
    }

    let mut handle = aggregate_handle.compress().to_bytes();
    for index in 0..shares.len() {
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
        let input = handle;
        handle = apply_decryption_factor(&input, &shares[index]).unwrap();
        let (statement, proof) = prove_dleq_with_nonce(
            &shares[index],
            &decryption_nonces[index],
            context,
            input,
            handle,
        )
        .unwrap();
        assert!(verify_dleq(&statement, &proof));
    }

    let decrypted_opening = curve25519_dalek::ristretto::CompressedRistretto(handle)
        .decompress()
        .unwrap();
    assert_eq!(
        aggregate_commitment - decrypted_opening,
        *G * Scalar::from(1_111_110u64)
    );
}
