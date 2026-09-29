use private_claims_proof_relation::{
    bid_commitment, claim_note_commitment, claim_note_merkle_path, claim_note_merkle_root,
    claim_nullifier, claim_value, redemption_nullifier, funded_bid_merkle_path, funded_bid_merkle_root,
    verify_claim_relation, verify_redemption_relation, ClaimStatement, ClaimWitness,
    RedemptionStatement, RedemptionWitness, MAX_FUNDED_BIDS,
};

fn fixture() -> (ClaimStatement, ClaimWitness) {
    let program_id = [0x11; 32];
    let auction_id = [0x22; 32];
    let output_mint = [0x44; 32];
    let amounts = [100, 120, 130, 140, 150, 160, 170, 180];
    let leaves: [[u8; 32]; MAX_FUNDED_BIDS] = std::array::from_fn(|index| {
        let bidder = [u8::try_from(index + 1).expect("bidder index fits"); 32];
        let bid_randomness = [0x50 + index as u8; 32];
        let claim_secret = [0x70 + index as u8; 32];
        bid_commitment(
            &program_id,
            &auction_id,
            &bidder,
            amounts[index],
            &bid_randomness,
            &claim_secret,
        )
    });

    let bid_index = 4u8;
    let index = usize::from(bid_index);
    let bidder = [u8::try_from(index + 1).expect("bidder index fits"); 32];
    let amount = amounts[index];
    let bid_randomness = [0x50 + bid_index; 32];
    let claim_secret = [0x70 + bid_index; 32];
    let note_randomness = [0x99; 32];
    let total_bid_amount = amounts.iter().copied().sum();
    let total_output_amount = 1_000_000;
    let nullifier = claim_nullifier(
        &program_id,
        &auction_id,
        &leaves[index],
        &claim_secret,
    );
    let value = claim_value(amount, total_bid_amount, total_output_amount)
        .expect("fixture has a valid allocation");
    let statement = ClaimStatement {
        program_id,
        auction_id,
        funded_bid_root: funded_bid_merkle_root(&leaves),
        output_mint,
        note_commitment: claim_note_commitment(
            &program_id,
            &auction_id,
            &output_mint,
            value,
            &nullifier,
            &note_randomness,
        ),
        nullifier,
        total_bid_amount,
        total_output_amount,
    };
    let witness = ClaimWitness {
        bidder,
        amount,
        bid_randomness,
        claim_secret,
        bid_index,
        bid_merkle_siblings: funded_bid_merkle_path(&leaves, bid_index)
            .expect("fixture index is in range"),
        note_randomness,
    };
    (statement, witness)
}

fn redemption_fixture() -> (RedemptionStatement, RedemptionWitness) {
    let (claim_statement, claim_witness) = fixture();
    let bid_commitment = bid_commitment(
        &claim_statement.program_id,
        &claim_statement.auction_id,
        &claim_witness.bidder,
        claim_witness.amount,
        &claim_witness.bid_randomness,
        &claim_witness.claim_secret,
    );
    let leaves: [[u8; 32]; MAX_FUNDED_BIDS] = std::array::from_fn(|index| {
        if index == usize::from(claim_witness.bid_index) {
            claim_statement.note_commitment
        } else {
            [0xa0 + index as u8; 32]
        }
    });
    let statement = RedemptionStatement {
        program_id: claim_statement.program_id,
        auction_id: claim_statement.auction_id,
        claim_note_root: claim_note_merkle_root(&leaves),
        output_mint: claim_statement.output_mint,
        destination: [0x56; 32],
        nullifier: redemption_nullifier(
            &claim_statement.program_id,
            &claim_statement.auction_id,
            &bid_commitment,
            &claim_witness.claim_secret,
        ),
        amount: claim_value(
            claim_witness.amount,
            claim_statement.total_bid_amount,
            claim_statement.total_output_amount,
        )
        .expect("fixture has a valid allocation"),
    };
    let witness = RedemptionWitness {
        bid_commitment,
        claim_secret: claim_witness.claim_secret,
        note_randomness: claim_witness.note_randomness,
        note_index: claim_witness.bid_index,
        note_merkle_siblings: claim_note_merkle_path(&leaves, claim_witness.bid_index)
            .expect("fixture index is in range"),
    };
    (statement, witness)
}

#[test]
fn valid_funded_bid_membership_produces_a_domain_bound_claim_note() {
    let (statement, witness) = fixture();

    assert!(verify_claim_relation(&statement, &witness));
    assert_eq!(statement.public_values().len(), 208);
}

#[test]
fn claim_relation_rejects_mutated_membership_and_private_openings() {
    let (statement, witness) = fixture();

    assert!(!verify_claim_relation(
        &statement,
        &ClaimWitness {
            amount: witness.amount + 1,
            ..witness
        }
    ));
    assert!(!verify_claim_relation(
        &statement,
        &ClaimWitness {
            bidder: [0xee; 32],
            ..witness
        }
    ));
    assert!(!verify_claim_relation(
        &statement,
        &ClaimWitness {
            claim_secret: [0xaa; 32],
            ..witness
        }
    ));
    assert!(!verify_claim_relation(
        &statement,
        &ClaimWitness {
            note_randomness: [0xbb; 32],
            ..witness
        }
    ));

    let mut bad_path = witness;
    bad_path.bid_merkle_siblings[1][0] ^= 1;
    assert!(!verify_claim_relation(&statement, &bad_path));
    assert!(!verify_claim_relation(
        &statement,
        &ClaimWitness {
            bid_index: 8,
            ..witness
        }
    ));
}

#[test]
fn claim_relation_rejects_mutated_public_domain_and_note_values() {
    let (statement, witness) = fixture();

    let mut bad_root = statement;
    bad_root.funded_bid_root[0] ^= 1;
    assert!(!verify_claim_relation(&bad_root, &witness));

    let mut bad_note = statement;
    bad_note.note_commitment[0] ^= 1;
    assert!(!verify_claim_relation(&bad_note, &witness));

    let mut bad_nullifier = statement;
    bad_nullifier.nullifier[0] ^= 1;
    assert!(!verify_claim_relation(&bad_nullifier, &witness));

    let mut bad_asset = statement;
    bad_asset.output_mint[0] ^= 1;
    assert!(!verify_claim_relation(&bad_asset, &witness));

    let mut bad_total = statement;
    bad_total.total_bid_amount += 1;
    assert!(!verify_claim_relation(&bad_total, &witness));
}

#[test]
fn allocation_is_bounded_and_rounding_dust_never_exceeds_output() {
    for (amount, q, y) in [
        (0, 10, 100),
        (11, 10, 100),
        (1, 0, 100),
        (1, 1, 0),
    ] {
        assert_eq!(claim_value(amount, q, y), None);
    }
    assert_eq!(claim_value(u64::MAX, 10, 100), None);

    let amounts = [2, 3, 5, 7, 11, 13, 17, 19];
    let q = amounts.iter().sum::<u64>();
    for y in [1, 19, 77, 1_000_000, u64::MAX] {
        let allocated = amounts
            .iter()
            .map(|amount| claim_value(*amount, q, y).expect("valid bounded bid"))
            .map(u128::from)
            .sum::<u128>();
        assert!(allocated <= u128::from(y));
    }

    assert_eq!(
        claim_value(150, 1_150, 1_000_000),
        Some(130_434)
    );
}

#[test]
fn valid_note_membership_proves_public_amount_and_nullifier_for_redemption() {
    let (statement, witness) = redemption_fixture();
    let claim_nullifier = claim_nullifier(
        &statement.program_id,
        &statement.auction_id,
        &witness.bid_commitment,
        &witness.claim_secret,
    );

    assert!(verify_redemption_relation(&statement, &witness));
    assert_ne!(statement.nullifier, claim_nullifier);
    let reused_claim_nullifier = RedemptionStatement {
        nullifier: claim_nullifier,
        ..statement
    };
    assert!(
        !verify_redemption_relation(&reused_claim_nullifier, &witness),
        "claim and redemption nullifiers must not correlate the two public actions"
    );
    assert_eq!(statement.public_values().len(), 200);
}

#[test]
fn redemption_rejects_mutated_note_path_secret_amount_and_asset() {
    let (statement, witness) = redemption_fixture();

    assert!(!verify_redemption_relation(
        &statement,
        &RedemptionWitness {
            claim_secret: [0xab; 32],
            ..witness
        }
    ));
    assert!(!verify_redemption_relation(
        &statement,
        &RedemptionWitness {
            note_index: 8,
            ..witness
        }
    ));
    let mut bad_path = witness;
    bad_path.note_merkle_siblings[2][0] ^= 1;
    assert!(!verify_redemption_relation(&statement, &bad_path));

    let mut bad_amount = statement;
    bad_amount.amount += 1;
    assert!(!verify_redemption_relation(&bad_amount, &witness));

    let mut bad_nullifier = statement;
    bad_nullifier.nullifier[0] ^= 1;
    assert!(!verify_redemption_relation(&bad_nullifier, &witness));

    let mut bad_asset = statement;
    bad_asset.output_mint[0] ^= 1;
    assert!(!verify_redemption_relation(&bad_asset, &witness));
}

#[test]
fn redemption_amount_must_be_positive() {
    let (statement, witness) = redemption_fixture();
    let no_value = RedemptionStatement {
        amount: 0,
        ..statement
    };
    assert!(!verify_redemption_relation(&no_value, &witness));
}