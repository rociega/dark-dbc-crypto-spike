#![no_std]

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha256};
use sha3::Sha3_512;

pub const MAX_BID_AMOUNT: u64 = (1u64 << 32) - 1;
pub const PUBLIC_VALUES_LEN: usize = 384;

const BID_COMMITMENT_DOMAIN: &[u8] = b"dark-dbc:funding-commitment:test-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FundingStatement {
    pub program_id: [u8; 32],
    pub auction_id: [u8; 32],
    pub bidder: [u8; 32],
    pub bid_commitment: [u8; 32],
    pub token_mint: [u8; 32],
    pub confidential_vault: [u8; 32],
    pub transfer_context_hash: [u8; 32],
    pub auditor_pubkey: [u8; 32],
    pub ciphertext_low: [u8; 64],
    pub ciphertext_high: [u8; 64],
}

impl FundingStatement {
    pub fn public_values(&self) -> [u8; PUBLIC_VALUES_LEN] {
        let mut output = [0u8; PUBLIC_VALUES_LEN];
        let mut offset = 0;
        for field in [
            &self.program_id,
            &self.auction_id,
            &self.bidder,
            &self.bid_commitment,
            &self.token_mint,
            &self.confidential_vault,
            &self.transfer_context_hash,
            &self.auditor_pubkey,
        ] {
            output[offset..offset + 32].copy_from_slice(field);
            offset += 32;
        }
        output[offset..offset + 64].copy_from_slice(&self.ciphertext_low);
        offset += 64;
        output[offset..offset + 64].copy_from_slice(&self.ciphertext_high);
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FundingWitness {
    pub amount: u64,
    pub bid_randomness: [u8; 32],
    pub claim_secret: [u8; 32],
    pub opening_low: [u8; 32],
    pub opening_high: [u8; 32],
}

/// Test-only commitment schema. This is deliberately not the selected
/// production hash; it gives the SP1 feasibility guest a concrete relation.
pub fn bid_commitment(
    program_id: &[u8; 32],
    auction_id: &[u8; 32],
    bidder: &[u8; 32],
    amount: u64,
    bid_randomness: &[u8; 32],
    claim_secret: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BID_COMMITMENT_DOMAIN);
    hasher.update(program_id);
    hasher.update(auction_id);
    hasher.update(bidder);
    hasher.update(amount.to_le_bytes());
    hasher.update(bid_randomness);
    hasher.update(claim_secret);
    hasher.finalize().into()
}

/// Checks one serialized ElGamal ciphertext component:
/// C = value*G + opening*H and D = opening*auditor_pubkey.
pub fn ciphertext_component_matches(
    pubkey_bytes: &[u8; 32],
    value: u64,
    opening_bytes: &[u8; 32],
    ciphertext_bytes: &[u8; 64],
) -> bool {
    let Some(pubkey) = CompressedRistretto(*pubkey_bytes).decompress() else {
        return false;
    };
    let Some(commitment_bytes) = ciphertext_bytes[..32].try_into().ok() else {
        return false;
    };
    let Some(handle_bytes) = ciphertext_bytes[32..].try_into().ok() else {
        return false;
    };
    let Some(commitment) = CompressedRistretto(commitment_bytes).decompress() else {
        return false;
    };
    let Some(handle) = CompressedRistretto(handle_bytes).decompress() else {
        return false;
    };
    let Some(opening) = Scalar::from_canonical_bytes(*opening_bytes).into_option() else {
        return false;
    };

    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let expected_commitment = RISTRETTO_BASEPOINT_POINT * Scalar::from(value) + h * opening;
    let expected_handle = pubkey * opening;
    commitment == expected_commitment && handle == expected_handle
}

pub fn split_ciphertexts_match(
    pubkey_bytes: &[u8; 32],
    amount: u64,
    openings: &[[u8; 32]; 2],
    ciphertexts: &[[u8; 64]; 2],
) -> bool {
    if amount == 0 || amount > MAX_BID_AMOUNT {
        return false;
    }

    let low = amount & 0xffff;
    let high = amount >> 16;
    ciphertext_component_matches(pubkey_bytes, low, &openings[0], &ciphertexts[0])
        && ciphertext_component_matches(pubkey_bytes, high, &openings[1], &ciphertexts[1])
}

/// Verifies the hidden amount against both the bidder's commitment and the
/// exact serialized auditor ciphertext pair supplied as public inputs.
pub fn verify_funding_relation(statement: &FundingStatement, witness: &FundingWitness) -> bool {
    if witness.amount == 0 || witness.amount > MAX_BID_AMOUNT {
        return false;
    }

    let low = witness.amount & 0xffff;
    let high = witness.amount >> 16;
    let expected_commitment = bid_commitment(
        &statement.program_id,
        &statement.auction_id,
        &statement.bidder,
        witness.amount,
        &witness.bid_randomness,
        &witness.claim_secret,
    );

    expected_commitment == statement.bid_commitment
        && ciphertext_component_matches(
            &statement.auditor_pubkey,
            low,
            &witness.opening_low,
            &statement.ciphertext_low,
        )
        && ciphertext_component_matches(
            &statement.auditor_pubkey,
            high,
            &witness.opening_high,
            &statement.ciphertext_high,
        )
}
