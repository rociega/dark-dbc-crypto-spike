#![no_std]

use sha2::{Digest, Sha256};

pub const PUBLIC_VALUES_LEN: usize = 200;
pub const COMMITMENT_DOMAIN: &[u8] = b"meteora-launch-shield:sealed-bid:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BidStatement {
    pub program_id: [u8; 32],
    pub auction_id: [u8; 32],
    pub bidder: [u8; 32],
    pub bid_commitment: [u8; 32],
    pub quote_mint: [u8; 32],
    pub quote_escrow: [u8; 32],
    pub max_bid_amount: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BidWitness {
    pub amount: u64,
    pub salt: [u8; 32],
}

impl BidStatement {
    /// Fixed public serialization: six 32-byte fields in declaration order,
    /// followed by max_bid_amount as an unsigned little-endian u64.
    pub fn public_values(&self) -> [u8; PUBLIC_VALUES_LEN] {
        let mut out = [0u8; PUBLIC_VALUES_LEN];
        let fields = [
            &self.program_id,
            &self.auction_id,
            &self.bidder,
            &self.bid_commitment,
            &self.quote_mint,
            &self.quote_escrow,
        ];
        let mut offset = 0;
        for field in fields {
            out[offset..offset + 32].copy_from_slice(field);
            offset += 32;
        }
        out[offset..offset + 8].copy_from_slice(&self.max_bid_amount.to_le_bytes());
        out
    }
}

/// V1 commitment schema:
/// SHA256(domain || program_id || auction_id || bidder ||
/// amount.to_le_bytes() || salt). The commitment intentionally does not
/// include quote mint, escrow, or max; those remain public proof context.
pub fn bid_commitment(statement: &BidStatement, amount: u64, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(statement.program_id);
    hasher.update(statement.auction_id);
    hasher.update(statement.bidder);
    hasher.update(amount.to_le_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

pub fn verify_bid(statement: &BidStatement, witness: &BidWitness) -> bool {
    witness.amount > 0
        && witness.amount <= statement.max_bid_amount
        && bid_commitment(statement, witness.amount, &witness.salt) == statement.bid_commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (BidStatement, BidWitness) {
        let witness = BidWitness {
            amount: 37,
            salt: [0xabu8; 32],
        };
        let mut statement = BidStatement {
            program_id: [1; 32],
            auction_id: [2; 32],
            bidder: [3; 32],
            bid_commitment: [0; 32],
            quote_mint: [4; 32],
            quote_escrow: [5; 32],
            max_bid_amount: 100,
        };
        statement.bid_commitment = bid_commitment(&statement, witness.amount, &witness.salt);
        (statement, witness)
    }

    #[test]
    fn valid_bid_and_exact_public_encoding() {
        let (statement, witness) = fixture();
        assert!(verify_bid(&statement, &witness));
        assert_eq!(statement.public_values().len(), PUBLIC_VALUES_LEN);
        assert_eq!(&statement.public_values()[192..], &100u64.to_le_bytes());
    }

    #[test]
    fn rejects_wrong_amount() {
        let (statement, mut witness) = fixture();
        witness.amount += 1;
        assert!(!verify_bid(&statement, &witness));
    }

    #[test]
    fn rejects_wrong_salt() {
        let (statement, mut witness) = fixture();
        witness.salt[0] ^= 1;
        assert!(!verify_bid(&statement, &witness));
    }

    macro_rules! context_mutation_test {
        ($name:ident, $field:ident) => {
            #[test]
            fn $name() {
                let (mut statement, witness) = fixture();
                statement.$field[0] ^= 1;
                assert!(!verify_bid(&statement, &witness));
            }
        };
    }

    context_mutation_test!(rejects_wrong_bidder, bidder);
    context_mutation_test!(rejects_wrong_auction, auction_id);

    #[test]
    fn rejects_wrong_maximum() {
        let (mut statement, witness) = fixture();
        statement.max_bid_amount = witness.amount - 1;
        assert!(!verify_bid(&statement, &witness));
    }

    #[test]
    fn rejects_wrong_commitment() {
        let (mut statement, witness) = fixture();
        statement.bid_commitment[0] ^= 1;
        assert!(!verify_bid(&statement, &witness));
    }

    #[test]
    fn rejects_zero_and_over_max() {
        let (statement, mut witness) = fixture();
        witness.amount = 0;
        assert!(!verify_bid(&statement, &witness));
        witness.amount = statement.max_bid_amount + 1;
        assert!(!verify_bid(&statement, &witness));
    }
}
