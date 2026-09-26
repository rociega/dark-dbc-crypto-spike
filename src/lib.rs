#![cfg(test)]

//! Host-only feasibility tests using Solana's current ElGamal SDK types.
//!
//! This verifies ciphertext combination, the PodElGamalPubkey byte
//! representation, deterministic 2-of-3 Shamir interpolation, candidate
//! masked-inversion arithmetic, test-only Chaum-Pedersen proofs for aggregate
//! decryption shares, and bounded discrete-log recovery. It is not a production
//! DKG, an audited MPC, an on-chain verifier, a Token-2022 validator test, or an
//! Anchor program.

use std::collections::HashMap;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha2::{Digest, Sha512};
use solana_zk_sdk::encryption::{
    elgamal::{ElGamalCiphertext, ElGamalPubkey, ElGamalSecretKey},
    pedersen::{G, H},
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
use spl_token_confidential_transfer_proof_generation::try_combine_lo_hi_ciphertexts;

const MAX_BIDS: usize = 8;
const MVP_MAX_BID: u64 = (1u64 << 32) - 1;
const MAX_AGGREGATE: u64 = MAX_BIDS as u64 * MVP_MAX_BID;

fn split_bid(amount: u64) -> (u64, u64) {
    (amount & 0xffff, amount >> 16)
}

fn encrypt_split_amount(pubkey: &ElGamalPubkey, amount: u64) -> ElGamalCiphertext {
    assert!(amount <= MVP_MAX_BID);
    let (lo, hi) = split_bid(amount);
    let ciphertext_lo = pubkey.encrypt_u64(lo);
    let ciphertext_hi = pubkey.encrypt_u64(hi);
    try_combine_lo_hi_ciphertexts(&ciphertext_lo, &ciphertext_hi, 16)
        .expect("16-bit shift must be supported")
}

fn ceil_sqrt(value: u64) -> u64 {
    let mut root = (value as f64).sqrt() as u64;
    while u128::from(root) * u128::from(root) < u128::from(value) {
        root += 1;
    }
    root
}

/// Recovers a discrete log only within the public, configured aggregate bound.
/// The target is public settlement data; this function never sees a secret.
fn bounded_discrete_log(target: &RistrettoPoint, max_value: u64) -> Option<u64> {
    let width = ceil_sqrt(max_value.checked_add(1)?);
    let mut baby_steps = HashMap::with_capacity(width as usize);
    let mut point = RistrettoPoint::default();
    for j in 0..width {
        baby_steps.insert(point.compress().to_bytes(), j);
        point += G;
    }

    let giant_step = G * Scalar::from(width);
    let negative_giant_step = -giant_step;
    let mut candidate_point = *target;
    let giant_steps = max_value / width + 1;
    for i in 0..=giant_steps {
        if let Some(&j) = baby_steps.get(&candidate_point.compress().to_bytes()) {
            let candidate = i.checked_mul(width)?.checked_add(j)?;
            if candidate <= max_value {
                return Some(candidate);
            }
        }
        candidate_point += negative_giant_step;
    }
    None
}

#[derive(Clone, Copy)]
struct DleqProof {
    commitment_base: RistrettoPoint,
    commitment_handle: RistrettoPoint,
    response: Scalar,
}

#[derive(Clone, Copy)]
struct DleqContext<'a> {
    domain: &'a [u8],
    trustee_set_id: &'a [u8],
    trustee_index: u8,
    aggregate_public_key: &'a RistrettoPoint,
    ciphertext_commitment: &'a RistrettoPoint,
    handle: &'a RistrettoPoint,
    verification_base: &'a RistrettoPoint,
}

fn dleq_challenge(
    context: &DleqContext<'_>,
    verification_share: &RistrettoPoint,
    partial_decryption: &RistrettoPoint,
    commitment_base: &RistrettoPoint,
    commitment_handle: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"dark-dbc:aggregate-decryption-share:dleq:v1");
    hasher.update((context.domain.len() as u64).to_le_bytes());
    hasher.update(context.domain);
    hasher.update((context.trustee_set_id.len() as u64).to_le_bytes());
    hasher.update(context.trustee_set_id);
    hasher.update([context.trustee_index]);
    for point in [
        context.aggregate_public_key,
        context.ciphertext_commitment,
        context.handle,
        context.verification_base,
        verification_share,
        partial_decryption,
        commitment_base,
        commitment_handle,
    ] {
        hasher.update(point.compress().as_bytes());
    }
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Test-only Chaum-Pedersen proof that `verification_share` and
/// `partial_decryption` use the same scalar. The caller supplies a nonce;
/// production nonce generation and proof encoding are intentionally absent.
fn prove_decryption_share(
    share: Scalar,
    nonce: Scalar,
    context: &DleqContext<'_>,
) -> (RistrettoPoint, RistrettoPoint, DleqProof) {
    let verification_share = context.verification_base * share;
    let partial_decryption = context.handle * share;
    let commitment_base = context.verification_base * nonce;
    let commitment_handle = context.handle * nonce;
    let challenge = dleq_challenge(
        context,
        &verification_share,
        &partial_decryption,
        &commitment_base,
        &commitment_handle,
    );
    let proof = DleqProof {
        commitment_base,
        commitment_handle,
        response: nonce + challenge * share,
    };

    (verification_share, partial_decryption, proof)
}

fn verify_decryption_share(
    context: &DleqContext<'_>,
    verification_share: &RistrettoPoint,
    partial_decryption: &RistrettoPoint,
    proof: &DleqProof,
) -> bool {
    let challenge = dleq_challenge(
        context,
        verification_share,
        partial_decryption,
        &proof.commitment_base,
        &proof.commitment_handle,
    );

    context.verification_base * proof.response
        == proof.commitment_base + verification_share * challenge
        && context.handle * proof.response
            == proof.commitment_handle + partial_decryption * challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ThresholdKeyFixture {
        aggregate_pubkey: ElGamalPubkey,
        pod_pubkey: PodElGamalPubkey,
        master_secret: Scalar,
        share_1: Scalar,
        share_2: Scalar,
        share_1_pubkey: ElGamalPubkey,
        share_2_pubkey: ElGamalPubkey,
    }

    /// Deterministic 2-of-3 Shamir secret-share fixture. The aggregate
    /// ElGamal public key is constructed from the full secret, so this is not
    /// a distributed key-generation protocol.
    fn threshold_key_fixture() -> ThresholdKeyFixture {
        let master_secret = Scalar::from(123_456_789u64);
        let slope = Scalar::from(987_654_321u64);
        let share_1 = master_secret + slope;
        let share_2 = master_secret + slope * Scalar::from(2u64);

        let master_secret_key = ElGamalSecretKey::from(master_secret);
        let aggregate_pubkey = ElGamalPubkey::new(&master_secret_key);
        let pod_pubkey: PodElGamalPubkey = aggregate_pubkey.into();

        let share_1_key = ElGamalSecretKey::from(share_1);
        let share_2_key = ElGamalSecretKey::from(share_2);
        let share_1_pubkey = ElGamalPubkey::new(&share_1_key);
        let share_2_pubkey = ElGamalPubkey::new(&share_2_key);

        ThresholdKeyFixture {
            aggregate_pubkey,
            pod_pubkey,
            master_secret,
            share_1,
            share_2,
            share_1_pubkey,
            share_2_pubkey,
        }
    }

    #[test]
    fn threshold_aggregate_key_round_trips_through_token_2022_pod_type() {
        let fixture = threshold_key_fixture();
        let decoded = ElGamalPubkey::try_from(fixture.pod_pubkey)
            .expect("the SDK public key must decode from PodElGamalPubkey");
        assert_eq!(decoded, fixture.aggregate_pubkey);
    }

    #[test]
    fn combined_ciphertext_pair_encrypts_the_original_bid_amount() {
        let fixture = threshold_key_fixture();
        for amount in [1, 65_535, 65_536, 123_456_789, MVP_MAX_BID] {
            let ciphertext = encrypt_split_amount(&fixture.aggregate_pubkey, amount);
            assert_eq!(
                ciphertext.decrypt_u32(&ElGamalSecretKey::from(fixture.master_secret)),
                Some(amount)
            );
        }
    }

    #[test]
    fn naive_shamir_public_key_interpolation_does_not_match_sdk_elgamal_key() {
        let fixture = threshold_key_fixture();
        let lambda_1 = Scalar::from(2u64);
        let lambda_2 = -Scalar::ONE;
        let naive_interpolated_pubkey = fixture.share_1_pubkey.get_point() * lambda_1
            + fixture.share_2_pubkey.get_point() * lambda_2;

        // ElGamalPubkey::new maps secret s to H / s. Thus public keys derived
        // independently from Shamir shares do not interpolate to H / s.
        // Producing the compatible group key without exposing s needs a
        // distributed inversion step, which is not implemented here.
        assert_ne!(
            naive_interpolated_pubkey,
            *fixture.aggregate_pubkey.get_point()
        );
    }

    #[test]
    fn degree_reduced_masked_inversion_derives_the_sdk_public_key_algebraically() {
        // This centrally simulated transcript checks the arithmetic for a
        // candidate passive-secure MPC approach; it is not a DKG or a security
        // proof. In particular, it omits authenticated channels, VSS, malicious
        // participant handling, and reviewed randomness generation.
        let secret = Scalar::from(123_456_789u64);
        let secret_slope = Scalar::from(987_654_321u64);
        let mask = Scalar::from(456_789_123u64);
        let mask_slope = Scalar::from(321_987_654u64);
        let indices = [1u64, 2, 3];
        let secret_shares = indices.map(|index| secret + secret_slope * Scalar::from(index));
        let mask_shares = indices.map(|index| mask + mask_slope * Scalar::from(index));
        let interpolation_weights = [Scalar::from(3u64), -Scalar::from(3u64), Scalar::ONE];

        // Each trustee locally multiplies its secret and mask shares, scales
        // by its Lagrange coefficient, and reshapes that value with a fresh
        // degree-one polynomial. These cross-shares are then summed locally.
        let degree_reduction_slopes = [
            Scalar::from(17u64),
            Scalar::from(23u64),
            Scalar::from(41u64),
        ];
        let masked_product_shares = indices.map(|recipient_index| {
            (0..indices.len())
                .map(|dealer| {
                    let weighted_product =
                        interpolation_weights[dealer] * secret_shares[dealer] * mask_shares[dealer];
                    weighted_product
                        + degree_reduction_slopes[dealer] * Scalar::from(recipient_index)
                })
                .sum::<Scalar>()
        });

        // Open the masked product z = secret * mask from two reshared values.
        let masked_product =
            Scalar::from(2u64) * masked_product_shares[0] - masked_product_shares[1];
        assert_eq!(masked_product, secret * mask);
        assert_ne!(masked_product, Scalar::ZERO);

        // Dividing each mask share by public z yields Shamir shares of 1/secret.
        // Publicly interpolate those shares as group points to get H/secret,
        // which is the SDK's PodElGamalPubkey-compatible public-key point.
        let inverse_shares = mask_shares.map(|share| share * masked_product.invert());
        let inverse_public_share_1 = *H * inverse_shares[0];
        let inverse_public_share_2 = *H * inverse_shares[1];
        let derived_public_key_point =
            inverse_public_share_1 * Scalar::from(2u64) - inverse_public_share_2;

        let sdk_public_key = ElGamalPubkey::new(&ElGamalSecretKey::from(secret));
        assert_eq!(derived_public_key_point, *sdk_public_key.get_point());
        let pod_key: PodElGamalPubkey = sdk_public_key.into();
        assert!(ElGamalPubkey::try_from(pod_key).is_ok());

        // The original shares of `secret`, not the inverse shares, are still
        // the threshold decryption shares for this SDK key.
        let ciphertext = sdk_public_key.encrypt_u64(987_654);
        let handle = ciphertext.handle.get_point();
        let partial_1 = handle * secret_shares[0];
        let partial_2 = handle * secret_shares[1];
        let combined = partial_1 * Scalar::from(2u64) - partial_2;
        let plaintext_point = ciphertext.commitment.get_point() - combined;
        assert_eq!(plaintext_point, G * Scalar::from(987_654u64));
    }

    #[test]
    fn two_shares_decrypt_only_the_aggregate_ciphertext_to_public_q() {
        let fixture = threshold_key_fixture();
        let amounts = [
            1,
            65_535,
            65_536,
            123_456,
            987_654,
            1_234_567,
            2_147_483_647,
            MVP_MAX_BID,
        ];
        let expected_q: u64 = amounts.iter().sum();
        assert_eq!(amounts.len(), MAX_BIDS);
        assert!(expected_q <= MAX_AGGREGATE);
        assert!(expected_q > u32::MAX as u64);

        let mut aggregate: Option<ElGamalCiphertext> = None;
        for amount in amounts {
            let ciphertext = encrypt_split_amount(&fixture.aggregate_pubkey, amount);
            aggregate = Some(match aggregate {
                Some(total) => total + ciphertext,
                None => ciphertext,
            });
        }
        let aggregate = aggregate.expect("eight positive bid ciphertexts");

        // 2-of-3 Lagrange coefficients for share indices x=1 and x=2:
        // lambda_1 = 2, lambda_2 = -1.
        let lambda_1 = Scalar::from(2u64);
        let lambda_2 = -Scalar::ONE;
        let handle = aggregate.handle.get_point();
        let domain = b"dark-dbc:test-auction:aggregate-settlement";
        let verification_base = &*H;
        let context_1 = DleqContext {
            domain,
            trustee_set_id: b"dark-dbc:test-trustee-set:v1",
            trustee_index: 1,
            aggregate_public_key: fixture.aggregate_pubkey.get_point(),
            ciphertext_commitment: aggregate.commitment.get_point(),
            handle,
            verification_base,
        };
        let context_2 = DleqContext {
            trustee_index: 2,
            ..context_1
        };
        let (verification_share_1, partial_1, proof_1) =
            prove_decryption_share(fixture.share_1, Scalar::from(71u64), &context_1);
        let (verification_share_2, partial_2, proof_2) =
            prove_decryption_share(fixture.share_2, Scalar::from(93u64), &context_2);
        assert!(verify_decryption_share(
            &context_1,
            &verification_share_1,
            &partial_1,
            &proof_1,
        ));
        assert!(verify_decryption_share(
            &context_2,
            &verification_share_2,
            &partial_2,
            &proof_2,
        ));
        let wrong_domain_context = DleqContext {
            domain: b"another-auction",
            ..context_1
        };
        assert!(!verify_decryption_share(
            &wrong_domain_context,
            &verification_share_1,
            &partial_1,
            &proof_1,
        ));
        let wrong_trustee_set_context = DleqContext {
            trustee_set_id: b"another-trustee-set",
            ..context_1
        };
        assert!(!verify_decryption_share(
            &wrong_trustee_set_context,
            &verification_share_1,
            &partial_1,
            &proof_1,
        ));
        let wrong_trustee_context = DleqContext {
            trustee_index: 3,
            ..context_1
        };
        assert!(!verify_decryption_share(
            &wrong_trustee_context,
            &verification_share_1,
            &partial_1,
            &proof_1,
        ));
        let wrong_aggregate_public_key = *fixture.aggregate_pubkey.get_point() + *verification_base;
        let wrong_public_key_context = DleqContext {
            aggregate_public_key: &wrong_aggregate_public_key,
            ..context_1
        };
        assert!(!verify_decryption_share(
            &wrong_public_key_context,
            &verification_share_1,
            &partial_1,
            &proof_1,
        ));
        let wrong_handle = handle + *verification_base;
        let wrong_handle_context = DleqContext {
            handle: &wrong_handle,
            ..context_1
        };
        assert!(!verify_decryption_share(
            &wrong_handle_context,
            &verification_share_1,
            &partial_1,
            &proof_1,
        ));
        let invalid_partial = partial_1 + *verification_base;
        assert!(!verify_decryption_share(
            &context_1,
            &verification_share_1,
            &invalid_partial,
            &proof_1,
        ));

        let combined_decryption = partial_1 * lambda_1 + partial_2 * lambda_2;

        let decrypted_point = aggregate.commitment.get_point() - combined_decryption;
        let expected_point = G * Scalar::from(expected_q);
        assert_eq!(decrypted_point, expected_point);
        assert_eq!(
            bounded_discrete_log(&decrypted_point, MAX_AGGREGATE),
            Some(expected_q)
        );

        // Sanity check that either individual share alone is not the aggregate
        // secret-key decryption. This is a fixture check, not a security proof.
        let one_share_point = aggregate.commitment.get_point() - partial_1;
        assert_ne!(one_share_point, expected_point);
        let other_share_point = aggregate.commitment.get_point() - partial_2;
        assert_ne!(other_share_point, expected_point);
    }

    #[test]
    fn bounded_dlog_rejects_points_outside_the_public_range() {
        let outside = G * Scalar::from(MAX_AGGREGATE + 1);
        assert_eq!(bounded_discrete_log(&outside, MAX_AGGREGATE), None);
    }
}
