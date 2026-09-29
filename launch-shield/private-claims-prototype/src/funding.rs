//! Host tests for the no_std funding relation against SDK-compatible fixtures.
//!
//! These tests do not create an SP1 proof or establish that Token-2022 accepted
//! a transfer. The mint, vault, and transfer-context fields are public inputs
//! that the calling program must validate against the successful CPI.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use private_claims_proof_relation::{
    bid_commitment, verify_funding_relation, FundingStatement, FundingWitness,
    MAX_BID_AMOUNT, PUBLIC_VALUES_LEN,
};
use solana_zk_sdk::encryption::pedersen::{G, H};

fn encrypt_component(pubkey: &RistrettoPoint, value: u64, opening: Scalar) -> [u8; 64] {
    let commitment = (G * Scalar::from(value) + *H * opening)
        .compress()
        .to_bytes();
    let handle = (pubkey * opening).compress().to_bytes();
    let mut ciphertext = [0u8; 64];
    ciphertext[..32].copy_from_slice(&commitment);
    ciphertext[32..].copy_from_slice(&handle);
    ciphertext
}

fn fixture(amount: u64) -> (FundingStatement, FundingWitness) {
    assert!(amount > 0 && amount <= MAX_BID_AMOUNT);
    let secret = Scalar::from(123_456_789u64);
    let auditor_pubkey = *H * secret.invert();
    let opening_low = Scalar::from(17u64);
    let opening_high = Scalar::from(91u64);
    let bid_randomness = [0x55; 32];
    let claim_secret = [0x66; 32];

    let mut statement = FundingStatement {
        program_id: [0x11; 32],
        auction_id: [0x22; 32],
        bidder: [0x33; 32],
        bid_commitment: [0; 32],
        token_mint: [0x44; 32],
        confidential_vault: [0x77; 32],
        transfer_context_hash: [0x88; 32],
        auditor_pubkey: auditor_pubkey.compress().to_bytes(),
        ciphertext_low: encrypt_component(
            &auditor_pubkey,
            amount & 0xffff,
            opening_low,
        ),
        ciphertext_high: encrypt_component(
            &auditor_pubkey,
            amount >> 16,
            opening_high,
        ),
    };
    statement.bid_commitment = bid_commitment(
        &statement.program_id,
        &statement.auction_id,
        &statement.bidder,
        amount,
        &bid_randomness,
        &claim_secret,
    );

    let witness = FundingWitness {
        amount,
        bid_randomness,
        claim_secret,
        opening_low: opening_low.to_bytes(),
        opening_high: opening_high.to_bytes(),
    };
    (statement, witness)
}

#[test]
fn valid_amount_opens_the_commitment_and_both_ciphertexts() {
    let (statement, witness) = fixture(123_456_789);

    assert!(verify_funding_relation(&statement, &witness));
    assert_eq!(statement.public_values().len(), PUBLIC_VALUES_LEN);
}

#[test]
fn amounts_at_ciphertext_chunk_boundaries_are_accepted() {
    for amount in [1, 0xffff, 0x1_0000, MAX_BID_AMOUNT] {
        let (statement, witness) = fixture(amount);
        assert!(
            verify_funding_relation(&statement, &witness),
            "expected amount {amount} to satisfy the relation"
        );
    }
}

#[test]
fn amount_mutation_and_out_of_range_amounts_are_rejected() {
    let (statement, witness) = fixture(123_456_789);

    assert!(!verify_funding_relation(
        &statement,
        &FundingWitness {
            amount: witness.amount + 1,
            ..witness
        }
    ));
    assert!(!verify_funding_relation(
        &statement,
        &FundingWitness { amount: 0, ..witness }
    ));
    assert!(!verify_funding_relation(
        &statement,
        &FundingWitness {
            amount: MAX_BID_AMOUNT + 1,
            ..witness
        }
    ));
}

#[test]
fn either_ciphertext_component_must_match_the_witness() {
    let (statement, witness) = fixture(123_456_789);

    let mut bad_low = statement;
    bad_low.ciphertext_low[0] ^= 1;
    assert!(!verify_funding_relation(&bad_low, &witness));

    let mut bad_high = statement;
    bad_high.ciphertext_high[0] ^= 1;
    assert!(!verify_funding_relation(&bad_high, &witness));
}

#[test]
fn noncanonical_openings_and_wrong_auditor_keys_are_rejected() {
    let (statement, witness) = fixture(123_456_789);
    assert!(!verify_funding_relation(
        &statement,
        &FundingWitness {
            opening_low: [0xff; 32],
            ..witness
        }
    ));

    let mut wrong_key = statement;
    wrong_key.auditor_pubkey =
        (*H * Scalar::from(987_654_321u64).invert()).compress().to_bytes();
    assert!(!verify_funding_relation(&wrong_key, &witness));
}