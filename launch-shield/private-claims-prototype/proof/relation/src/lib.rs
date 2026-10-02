#![no_std]

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha256};
use sha3::Sha3_512;

pub mod aggregate;
pub mod threshold;

pub const MAX_BID_AMOUNT: u64 = (1u64 << 32) - 1;
pub const PUBLIC_VALUES_LEN: usize = 384;
pub const MAX_FUNDED_BIDS: usize = 8;
pub const BID_MERKLE_DEPTH: usize = 3;
pub const MAX_TOTAL_BID_AMOUNT: u64 = MAX_BID_AMOUNT * MAX_FUNDED_BIDS as u64;
pub const CLAIM_PUBLIC_VALUES_LEN: usize = 208;
pub const REDEMPTION_PUBLIC_VALUES_LEN: usize = 200;

const BID_COMMITMENT_DOMAIN: &[u8] = b"private-claims:funding-commitment:test-v1";
const BID_LEAF_DOMAIN: &[u8] = b"private-claims:funded-bid-leaf:test-v1";
const BID_NODE_DOMAIN: &[u8] = b"private-claims:funded-bid-node:test-v1";
const CLAIM_NULLIFIER_DOMAIN: &[u8] = b"private-claims:nullifier:test-v1";
const REDEMPTION_NULLIFIER_DOMAIN: &[u8] = b"private-claims:redemption-nullifier:test-v1";
const CLAIM_NOTE_DOMAIN: &[u8] = b"private-claims:note:test-v1";
const NOTE_LEAF_DOMAIN: &[u8] = b"private-claims:note-leaf:test-v1";
const NOTE_NODE_DOMAIN: &[u8] = b"private-claims:note-node:test-v1";
const PROOF_CONTEXT_ACCOUNT_DOMAIN: &[u8] = b"private-claims:proof-context-account:test-v1";
const ACCEPTED_TRANSFER_CONTEXT_DOMAIN: &[u8] = b"private-claims:accepted-transfer-context:test-v1";

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

pub struct AcceptedTransferContext<'a> {
    pub program_id: &'a [u8; 32],
    pub pool_account: &'a [u8; 32],
    pub source_account: &'a [u8; 32],
    pub funding_mint: &'a [u8; 32],
    pub confidential_vault: &'a [u8; 32],
    pub authority: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; 32],
    pub confidential_vault_elgamal_pubkey: &'a [u8; 32],
    pub new_source_decryptable_balance: &'a [u8],
    pub auditor_ciphertexts: &'a [u8; 128],
    pub equality_context_hash: &'a [u8; 32],
    pub ciphertext_validity_context_hash: &'a [u8; 32],
    pub range_context_hash: &'a [u8; 32],
}

impl AcceptedTransferContext<'_> {
    pub fn hash(&self) -> [u8; 32] {
        hash_domain(
            ACCEPTED_TRANSFER_CONTEXT_DOMAIN,
            &[
                self.program_id,
                self.pool_account,
                self.source_account,
                self.funding_mint,
                self.confidential_vault,
                self.authority,
                self.auditor_pubkey,
                self.confidential_vault_elgamal_pubkey,
                self.new_source_decryptable_balance,
                self.auditor_ciphertexts,
                self.equality_context_hash,
                self.ciphertext_validity_context_hash,
                self.range_context_hash,
            ],
        )
    }
}

pub fn proof_context_account_hash(
    account_key: &[u8; 32],
    owner: &[u8; 32],
    data: &[u8],
) -> [u8; 32] {
    hash_domain(PROOF_CONTEXT_ACCOUNT_DOMAIN, &[account_key, owner, data])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FundingWitness {
    pub amount: u64,
    pub bid_randomness: [u8; 32],
    pub claim_secret: [u8; 32],
    pub opening_low: [u8; 32],
    pub opening_high: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimStatement {
    pub program_id: [u8; 32],
    pub auction_id: [u8; 32],
    pub funded_bid_root: [u8; 32],
    pub output_mint: [u8; 32],
    pub note_commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub total_bid_amount: u64,
    pub total_output_amount: u64,
}

impl ClaimStatement {
    pub fn public_values(&self) -> [u8; CLAIM_PUBLIC_VALUES_LEN] {
        let mut output = [0u8; CLAIM_PUBLIC_VALUES_LEN];
        let mut offset = 0;
        for field in [
            &self.program_id,
            &self.auction_id,
            &self.funded_bid_root,
            &self.output_mint,
            &self.note_commitment,
            &self.nullifier,
        ] {
            output[offset..offset + 32].copy_from_slice(field);
            offset += 32;
        }
        output[offset..offset + 8].copy_from_slice(&self.total_bid_amount.to_le_bytes());
        offset += 8;
        output[offset..offset + 8].copy_from_slice(&self.total_output_amount.to_le_bytes());
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimWitness {
    pub bidder: [u8; 32],
    pub amount: u64,
    pub bid_randomness: [u8; 32],
    pub claim_secret: [u8; 32],
    pub bid_index: u8,
    pub bid_merkle_siblings: [[u8; 32]; BID_MERKLE_DEPTH],
    pub note_randomness: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedemptionStatement {
    pub program_id: [u8; 32],
    pub auction_id: [u8; 32],
    pub claim_note_root: [u8; 32],
    pub output_mint: [u8; 32],
    pub destination: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount: u64,
}

impl RedemptionStatement {
    pub fn public_values(&self) -> [u8; REDEMPTION_PUBLIC_VALUES_LEN] {
        let mut output = [0u8; REDEMPTION_PUBLIC_VALUES_LEN];
        let mut offset = 0;
        for field in [
            &self.program_id,
            &self.auction_id,
            &self.claim_note_root,
            &self.output_mint,
            &self.destination,
            &self.nullifier,
        ] {
            output[offset..offset + 32].copy_from_slice(field);
            offset += 32;
        }
        output[offset..offset + 8].copy_from_slice(&self.amount.to_le_bytes());
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedemptionWitness {
    pub bid_commitment: [u8; 32],
    pub claim_secret: [u8; 32],
    pub note_randomness: [u8; 32],
    pub note_index: u8,
    pub note_merkle_siblings: [[u8; 32]; BID_MERKLE_DEPTH],
}

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

pub fn claim_nullifier(
    program_id: &[u8; 32],
    auction_id: &[u8; 32],
    bid_commitment: &[u8; 32],
    claim_secret: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        CLAIM_NULLIFIER_DOMAIN,
        &[program_id, auction_id, bid_commitment, claim_secret],
    )
}

pub fn redemption_nullifier(
    program_id: &[u8; 32],
    auction_id: &[u8; 32],
    bid_commitment: &[u8; 32],
    claim_secret: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        REDEMPTION_NULLIFIER_DOMAIN,
        &[program_id, auction_id, bid_commitment, claim_secret],
    )
}

pub fn claim_note_commitment(
    program_id: &[u8; 32],
    auction_id: &[u8; 32],
    output_mint: &[u8; 32],
    value: u64,
    nullifier: &[u8; 32],
    note_randomness: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        CLAIM_NOTE_DOMAIN,
        &[
            program_id,
            auction_id,
            output_mint,
            &value.to_le_bytes(),
            nullifier,
            note_randomness,
        ],
    )
}

pub fn funded_bid_merkle_root(leaves: &[[u8; 32]; MAX_FUNDED_BIDS]) -> [u8; 32] {
    merkle_levels(leaves, BID_LEAF_DOMAIN, BID_NODE_DOMAIN)[BID_MERKLE_DEPTH][0]
}

pub fn funded_bid_merkle_path(
    leaves: &[[u8; 32]; MAX_FUNDED_BIDS],
    index: u8,
) -> Option<[[u8; 32]; BID_MERKLE_DEPTH]> {
    if usize::from(index) >= MAX_FUNDED_BIDS {
        return None;
    }
    let levels = merkle_levels(leaves, BID_LEAF_DOMAIN, BID_NODE_DOMAIN);
    let mut path = [[0u8; 32]; BID_MERKLE_DEPTH];
    let mut cursor = usize::from(index);
    for (depth, sibling) in path.iter_mut().enumerate() {
        *sibling = levels[depth][cursor ^ 1];
        cursor >>= 1;
    }
    Some(path)
}

pub fn claim_note_merkle_root(leaves: &[[u8; 32]; MAX_FUNDED_BIDS]) -> [u8; 32] {
    merkle_levels(leaves, NOTE_LEAF_DOMAIN, NOTE_NODE_DOMAIN)[BID_MERKLE_DEPTH][0]
}

pub fn claim_note_merkle_path(
    leaves: &[[u8; 32]; MAX_FUNDED_BIDS],
    index: u8,
) -> Option<[[u8; 32]; BID_MERKLE_DEPTH]> {
    merkle_path(leaves, index, NOTE_LEAF_DOMAIN, NOTE_NODE_DOMAIN)
}

pub fn claim_value(amount: u64, total_bid_amount: u64, total_output_amount: u64) -> Option<u64> {
    if amount == 0
        || amount > MAX_BID_AMOUNT
        || total_bid_amount == 0
        || total_bid_amount > MAX_TOTAL_BID_AMOUNT
        || amount > total_bid_amount
        || total_output_amount == 0
    {
        return None;
    }

    let numerator = u128::from(amount).checked_mul(u128::from(total_output_amount))?;
    let denominator = u128::from(total_bid_amount);
    let quotient = numerator.checked_div(denominator)?;
    let value = u64::try_from(quotient).ok()?;
    let lower_bound = quotient.checked_mul(denominator)?;
    let upper_bound = quotient.checked_add(1)?.checked_mul(denominator)?;
    if lower_bound > numerator || numerator >= upper_bound || value > total_output_amount {
        return None;
    }
    Some(value)
}

pub fn verify_redemption_relation(
    statement: &RedemptionStatement,
    witness: &RedemptionWitness,
) -> bool {
    if statement.amount == 0 || usize::from(witness.note_index) >= MAX_FUNDED_BIDS {
        return false;
    }

    let expected_claim_nullifier = claim_nullifier(
        &statement.program_id,
        &statement.auction_id,
        &witness.bid_commitment,
        &witness.claim_secret,
    );
    let expected_redemption_nullifier = redemption_nullifier(
        &statement.program_id,
        &statement.auction_id,
        &witness.bid_commitment,
        &witness.claim_secret,
    );
    if expected_redemption_nullifier != statement.nullifier {
        return false;
    }
    let note_commitment = claim_note_commitment(
        &statement.program_id,
        &statement.auction_id,
        &statement.output_mint,
        statement.amount,
        &expected_claim_nullifier,
        &witness.note_randomness,
    );
    verify_merkle_path(
        &note_commitment,
        witness.note_index,
        &witness.note_merkle_siblings,
        &statement.claim_note_root,
        NOTE_LEAF_DOMAIN,
        NOTE_NODE_DOMAIN,
    )
}

pub fn verify_claim_relation(statement: &ClaimStatement, witness: &ClaimWitness) -> bool {
    if usize::from(witness.bid_index) >= MAX_FUNDED_BIDS {
        return false;
    }
    let Some(value) = claim_value(
        witness.amount,
        statement.total_bid_amount,
        statement.total_output_amount,
    ) else {
        return false;
    };

    let commitment = bid_commitment(
        &statement.program_id,
        &statement.auction_id,
        &witness.bidder,
        witness.amount,
        &witness.bid_randomness,
        &witness.claim_secret,
    );
    if !verify_merkle_path(
        &commitment,
        witness.bid_index,
        &witness.bid_merkle_siblings,
        &statement.funded_bid_root,
        BID_LEAF_DOMAIN,
        BID_NODE_DOMAIN,
    ) {
        return false;
    }

    claim_nullifier(
        &statement.program_id,
        &statement.auction_id,
        &commitment,
        &witness.claim_secret,
    ) == statement.nullifier
        && claim_note_commitment(
            &statement.program_id,
            &statement.auction_id,
            &statement.output_mint,
            value,
            &statement.nullifier,
            &witness.note_randomness,
        ) == statement.note_commitment
}

fn merkle_levels(
    leaves: &[[u8; 32]; MAX_FUNDED_BIDS],
    leaf_domain: &[u8],
    node_domain: &[u8],
) -> [[[u8; 32]; MAX_FUNDED_BIDS]; BID_MERKLE_DEPTH + 1] {
    let mut levels = [[[0u8; 32]; MAX_FUNDED_BIDS]; BID_MERKLE_DEPTH + 1];
    for (index, leaf) in leaves.iter().enumerate() {
        levels[0][index] = hash_domain(leaf_domain, &[leaf]);
    }
    for depth in 1..=BID_MERKLE_DEPTH {
        let nodes_at_depth = MAX_FUNDED_BIDS >> depth;
        for index in 0..nodes_at_depth {
            levels[depth][index] = hash_domain(
                node_domain,
                &[
                    &levels[depth - 1][index * 2],
                    &levels[depth - 1][index * 2 + 1],
                ],
            );
        }
    }
    levels
}

fn merkle_path(
    leaves: &[[u8; 32]; MAX_FUNDED_BIDS],
    index: u8,
    leaf_domain: &[u8],
    node_domain: &[u8],
) -> Option<[[u8; 32]; BID_MERKLE_DEPTH]> {
    if usize::from(index) >= MAX_FUNDED_BIDS {
        return None;
    }
    let levels = merkle_levels(leaves, leaf_domain, node_domain);
    let mut path = [[0u8; 32]; BID_MERKLE_DEPTH];
    let mut cursor = usize::from(index);
    for (depth, sibling) in path.iter_mut().enumerate() {
        *sibling = levels[depth][cursor ^ 1];
        cursor >>= 1;
    }
    Some(path)
}

fn verify_merkle_path(
    leaf: &[u8; 32],
    index: u8,
    siblings: &[[u8; 32]; BID_MERKLE_DEPTH],
    expected_root: &[u8; 32],
    leaf_domain: &[u8],
    node_domain: &[u8],
) -> bool {
    if usize::from(index) >= MAX_FUNDED_BIDS {
        return false;
    }
    let mut node = hash_domain(leaf_domain, &[leaf]);
    let mut cursor = usize::from(index);
    for sibling in siblings {
        node = if cursor & 1 == 0 {
            hash_domain(node_domain, &[&node, sibling])
        } else {
            hash_domain(node_domain, &[sibling, &node])
        };
        cursor >>= 1;
    }
    &node == expected_root
}

fn hash_domain(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn ciphertext_component_matches(
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

fn decompress_elgamal_ciphertext(
    ciphertext: &[u8; 64],
) -> Option<(RistrettoPoint, RistrettoPoint)> {
    let commitment_bytes: [u8; 32] = ciphertext[..32].try_into().ok()?;
    let handle_bytes: [u8; 32] = ciphertext[32..].try_into().ok()?;
    let commitment = CompressedRistretto(commitment_bytes).decompress()?;
    let handle = CompressedRistretto(handle_bytes).decompress()?;
    Some((commitment, handle))
}

pub fn is_valid_elgamal_ciphertext(ciphertext: &[u8; 64]) -> bool {
    decompress_elgamal_ciphertext(ciphertext).is_some()
}

pub fn add_elgamal_ciphertexts(left: &[u8; 64], right: &[u8; 64]) -> Option<[u8; 64]> {
    let (left_commitment, left_handle) = decompress_elgamal_ciphertext(left)?;
    let (right_commitment, right_handle) = decompress_elgamal_ciphertext(right)?;
    let commitment_sum = (left_commitment + right_commitment).compress();
    let handle_sum = (left_handle + right_handle).compress();

    let mut sum = [0; 64];
    sum[..32].copy_from_slice(commitment_sum.as_bytes());
    sum[32..].copy_from_slice(handle_sum.as_bytes());
    Some(sum)
}

#[cfg(test)]
mod elgamal_ciphertext_tests {
    use super::{add_elgamal_ciphertexts, is_valid_elgamal_ciphertext};
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};

    fn encode_ciphertext(commitment_scalar: u64, handle_scalar: u64) -> [u8; 64] {
        let commitment = (RISTRETTO_BASEPOINT_POINT * Scalar::from(commitment_scalar)).compress();
        let handle = (RISTRETTO_BASEPOINT_POINT * Scalar::from(handle_scalar)).compress();
        let mut ciphertext = [0; 64];
        ciphertext[..32].copy_from_slice(commitment.as_bytes());
        ciphertext[32..].copy_from_slice(handle.as_bytes());
        ciphertext
    }

    #[test]
    fn ciphertext_addition_sums_both_ristretto_components() {
        let left = encode_ciphertext(3, 7);
        let right = encode_ciphertext(5, 11);
        let expected = encode_ciphertext(8, 18);

        assert_eq!(add_elgamal_ciphertexts(&left, &right), Some(expected));
    }

    #[test]
    fn zero_ciphertext_is_the_additive_identity() {
        let zero = [0; 64];
        let value = encode_ciphertext(13, 17);

        assert!(is_valid_elgamal_ciphertext(&zero));
        assert_eq!(add_elgamal_ciphertexts(&zero, &value), Some(value));
        assert_eq!(add_elgamal_ciphertexts(&value, &zero), Some(value));
    }

    #[test]
    fn malformed_compressed_points_are_rejected() {
        let malformed = [u8::MAX; 64];
        let zero = [0; 64];

        assert!(!is_valid_elgamal_ciphertext(&malformed));
        assert_eq!(add_elgamal_ciphertexts(&malformed, &zero), None);
    }
}
