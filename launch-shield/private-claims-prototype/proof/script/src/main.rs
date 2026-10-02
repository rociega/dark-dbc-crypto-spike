use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use private_claims_proof_relation::{
    add_elgamal_ciphertexts,
    aggregate::{
        verify_aggregate_decryption_relation, verify_trustee_key_setup_relation,
        AggregateDecryptionStatement, AggregateDecryptionWitness, TrusteeKeySetupStatement,
    },
    bid_commitment, claim_note_commitment, claim_note_merkle_path, claim_note_merkle_root,
    claim_nullifier, funded_bid_merkle_path, funded_bid_merkle_root, proof_context_account_hash,
    redemption_nullifier,
    threshold::{
        aggregate_decryption_context_hash, apply_decryption_factor, apply_inverse_key_factor,
        key_transform_context_hash, prove_dleq_with_nonce, solana_pedersen_h, AggregateComponent,
        DleqProof, TrusteeDecryptionStep, TrusteeKeyTransformStep, TRUSTEE_COUNT,
    },
    verify_claim_relation, verify_redemption_relation, AcceptedTransferContext, ClaimStatement,
    ClaimWitness, FundingStatement, FundingWitness, RedemptionStatement, RedemptionWitness,
    MAX_BID_AMOUNT, MAX_FUNDED_BIDS,
};
use sha3::Sha3_512;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient, SP1Stdin},
    Elf, HashableKey, ProvingKey,
};
use std::{env, fs, path::Path};

const FUNDING_GUEST_ELF: Elf = Elf::Static(include_bytes!(env!("PRIVATE_CLAIMS_GUEST_ELF")));
const SP1_PROOF_LEN: usize = 356;

fn encrypt_component(pubkey: &RistrettoPoint, value: u64, opening: Scalar) -> [u8; 64] {
    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let commitment = (RISTRETTO_BASEPOINT_POINT * Scalar::from(value) + h * opening)
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
    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let auditor_pubkey = h * secret.invert();
    let opening_low = Scalar::from(17u64);
    let opening_high = Scalar::from(91u64);
    let bid_randomness = [0x55; 32];
    let claim_secret = [0x66; 32];
    let program_id = [0x11; 32];
    let auction_id = [0x22; 32];
    let bidder = [0x33; 32];
    let token_mint = [0x44; 32];
    let confidential_vault = [0x77; 32];
    let confidential_vault_elgamal_pubkey = [0x99; 32];
    let ciphertext_low = encrypt_component(&auditor_pubkey, amount & 0xffff, opening_low);
    let ciphertext_high = encrypt_component(&auditor_pubkey, amount >> 16, opening_high);
    let mut auditor_ciphertexts = [0u8; 128];
    auditor_ciphertexts[..64].copy_from_slice(&ciphertext_low);
    auditor_ciphertexts[64..].copy_from_slice(&ciphertext_high);
    let new_source_decryptable_balance = [0u8; 36];
    let equality_context_key = [0xa1; 32];
    let equality_context_owner = [0xb1; 32];
    let equality_context_hash = proof_context_account_hash(
        &equality_context_key,
        &equality_context_owner,
        &[0x01, 0x02],
    );
    let ciphertext_validity_context_key = [0xa2; 32];
    let ciphertext_validity_context_owner = [0xb2; 32];
    let ciphertext_validity_context_hash = proof_context_account_hash(
        &ciphertext_validity_context_key,
        &ciphertext_validity_context_owner,
        &[0x03, 0x04],
    );
    let range_context_key = [0xa3; 32];
    let range_context_owner = [0xb3; 32];
    let range_context_hash =
        proof_context_account_hash(&range_context_key, &range_context_owner, &[0x05, 0x06]);
    let transfer_context_hash = AcceptedTransferContext {
        program_id: &program_id,
        pool_account: &[0x12; 32],
        source_account: &[0x13; 32],
        funding_mint: &token_mint,
        confidential_vault: &confidential_vault,
        authority: &bidder,
        auditor_pubkey: &auditor_pubkey.compress().to_bytes(),
        confidential_vault_elgamal_pubkey: &confidential_vault_elgamal_pubkey,
        new_source_decryptable_balance: &new_source_decryptable_balance,
        auditor_ciphertexts: &auditor_ciphertexts,
        equality_context_hash: &equality_context_hash,
        ciphertext_validity_context_hash: &ciphertext_validity_context_hash,
        range_context_hash: &range_context_hash,
    }
    .hash();

    let mut statement = FundingStatement {
        program_id,
        auction_id,
        bidder,
        bid_commitment: [0; 32],
        token_mint,
        confidential_vault,
        transfer_context_hash,
        auditor_pubkey: auditor_pubkey.compress().to_bytes(),
        ciphertext_low,
        ciphertext_high,
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

fn stdin_for(statement: &FundingStatement, witness: &FundingWitness) -> SP1Stdin {
    let low_commitment: [u8; 32] = statement.ciphertext_low[..32]
        .try_into()
        .expect("low commitment has 32 bytes");
    let low_handle: [u8; 32] = statement.ciphertext_low[32..]
        .try_into()
        .expect("low handle has 32 bytes");
    let high_commitment: [u8; 32] = statement.ciphertext_high[..32]
        .try_into()
        .expect("high commitment has 32 bytes");
    let high_handle: [u8; 32] = statement.ciphertext_high[32..]
        .try_into()
        .expect("high handle has 32 bytes");

    let mut stdin = SP1Stdin::new();
    stdin.write(&0u8);
    stdin.write(&statement.program_id);
    stdin.write(&statement.auction_id);
    stdin.write(&statement.bidder);
    stdin.write(&statement.bid_commitment);
    stdin.write(&statement.token_mint);
    stdin.write(&statement.confidential_vault);
    stdin.write(&statement.transfer_context_hash);
    stdin.write(&statement.auditor_pubkey);
    stdin.write(&low_commitment);
    stdin.write(&low_handle);
    stdin.write(&high_commitment);
    stdin.write(&high_handle);
    stdin.write(&witness.amount);
    stdin.write(&witness.bid_randomness);
    stdin.write(&witness.claim_secret);
    stdin.write(&witness.opening_low);
    stdin.write(&witness.opening_high);
    stdin
}

fn claim_fixture() -> (ClaimStatement, ClaimWitness) {
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
    let amount = amounts[index];
    let bid_randomness = [0x50 + bid_index; 32];
    let claim_secret = [0x70 + bid_index; 32];
    let nullifier = claim_nullifier(&program_id, &auction_id, &leaves[index], &claim_secret);
    let note_randomness = [0x99; 32];
    let total_bid_amount = amounts.iter().sum();
    let total_output_amount = 1_000_000;
    let value =
        private_claims_proof_relation::claim_value(amount, total_bid_amount, total_output_amount)
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
        bidder: [u8::try_from(index + 1).expect("bidder index fits"); 32],
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

fn claim_stdin_for(statement: &ClaimStatement, witness: &ClaimWitness) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&1u8);
    stdin.write(&statement.program_id);
    stdin.write(&statement.auction_id);
    stdin.write(&statement.funded_bid_root);
    stdin.write(&statement.output_mint);
    stdin.write(&statement.note_commitment);
    stdin.write(&statement.nullifier);
    stdin.write(&statement.total_bid_amount);
    stdin.write(&statement.total_output_amount);
    stdin.write(&witness.bidder);
    stdin.write(&witness.amount);
    stdin.write(&witness.bid_randomness);
    stdin.write(&witness.claim_secret);
    stdin.write(&witness.bid_index);
    for sibling in &witness.bid_merkle_siblings {
        stdin.write(sibling);
    }
    stdin.write(&witness.note_randomness);
    stdin
}

fn redemption_fixture() -> (RedemptionStatement, RedemptionWitness) {
    let (claim_statement, claim_witness) = claim_fixture();
    let bid_commitment = bid_commitment(
        &claim_statement.program_id,
        &claim_statement.auction_id,
        &claim_witness.bidder,
        claim_witness.amount,
        &claim_witness.bid_randomness,
        &claim_witness.claim_secret,
    );
    let claim_notes: [[u8; 32]; MAX_FUNDED_BIDS] = std::array::from_fn(|index| {
        if index == usize::from(claim_witness.bid_index) {
            claim_statement.note_commitment
        } else {
            [0xa0 + index as u8; 32]
        }
    });
    let statement = RedemptionStatement {
        program_id: claim_statement.program_id,
        auction_id: claim_statement.auction_id,
        claim_note_root: claim_note_merkle_root(&claim_notes),
        output_mint: claim_statement.output_mint,
        destination: [0x56; 32],
        nullifier: redemption_nullifier(
            &claim_statement.program_id,
            &claim_statement.auction_id,
            &bid_commitment,
            &claim_witness.claim_secret,
        ),
        amount: private_claims_proof_relation::claim_value(
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
        note_merkle_siblings: claim_note_merkle_path(&claim_notes, claim_witness.bid_index)
            .expect("fixture index is in range"),
    };
    (statement, witness)
}

fn redemption_stdin_for(statement: &RedemptionStatement, witness: &RedemptionWitness) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&2u8);
    stdin.write(&statement.program_id);
    stdin.write(&statement.auction_id);
    stdin.write(&statement.claim_note_root);
    stdin.write(&statement.output_mint);
    stdin.write(&statement.destination);
    stdin.write(&statement.nullifier);
    stdin.write(&statement.amount);
    stdin.write(&witness.bid_commitment);
    stdin.write(&witness.claim_secret);
    stdin.write(&witness.note_randomness);
    stdin.write(&witness.note_index);
    for sibling in &witness.note_merkle_siblings {
        stdin.write(sibling);
    }
    stdin
}

// These deterministic factors, nonces, ciphertexts, and account identifiers are
// synthetic fixtures for local tests only; they are not a production key ceremony.
fn trustee_fixtures() -> (
    TrusteeKeySetupStatement,
    [TrusteeKeyTransformStep; TRUSTEE_COUNT],
    [Scalar; TRUSTEE_COUNT],
) {
    let factors = [13u64, 17, 19].map(Scalar::from);
    let program_id = [0x21; 32];
    let funding_mint = [0x24; 32];
    let key_epoch = [0x26; 32];
    let trustee_ids = [[0x27; 32], [0x28; 32], [0x29; 32]];
    let verification_shares =
        factors.map(|factor| (RISTRETTO_BASEPOINT_POINT * factor).compress().to_bytes());
    let combined_factor = factors.iter().copied().product::<Scalar>();
    let auditor_pubkey =
        (RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes())
            * combined_factor.invert())
        .compress()
        .to_bytes();
    let mut current_key = solana_pedersen_h();
    let steps = std::array::from_fn(|index| {
        let trustee_index = u8::try_from(index + 1).expect("trustee index fits");
        let previous_key = current_key;
        current_key = apply_inverse_key_factor(&current_key, &factors[index])
            .expect("fixture key transform is valid");
        let context = key_transform_context_hash(
            &program_id,
            &funding_mint,
            &key_epoch,
            &trustee_ids[index],
            trustee_index,
        )
        .expect("fixture key context is valid");
        let (_, proof) = prove_dleq_with_nonce(
            &factors[index],
            &Scalar::from(41 + index as u64 * 2),
            context,
            current_key,
            previous_key,
        )
        .expect("fixture DLEQ proof is valid");
        TrusteeKeyTransformStep {
            trustee_id: trustee_ids[index],
            derived_public_key: current_key,
            proof,
        }
    });
    let statement = TrusteeKeySetupStatement {
        program_id,
        funding_mint,
        auditor_pubkey,
        key_epoch,
        trustee_ids,
        verification_shares,
    };
    (statement, steps, factors)
}

fn trustee_key_setup_stdin_for(
    statement: &TrusteeKeySetupStatement,
    steps: &[TrusteeKeyTransformStep; TRUSTEE_COUNT],
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&4u8);
    stdin.write(&statement.program_id);
    stdin.write(&statement.funding_mint);
    stdin.write(&statement.auditor_pubkey);
    stdin.write(&statement.key_epoch);
    for trustee_id in &statement.trustee_ids {
        stdin.write(trustee_id);
    }
    for share in &statement.verification_shares {
        stdin.write(share);
    }
    write_key_setup_steps(&mut stdin, steps);
    stdin
}

fn write_dleq_proof(stdin: &mut SP1Stdin, proof: &DleqProof) {
    stdin.write(&proof.commitment_base);
    stdin.write(&proof.commitment_input);
    stdin.write(&proof.response);
}

fn write_key_setup_steps(stdin: &mut SP1Stdin, steps: &[TrusteeKeyTransformStep; TRUSTEE_COUNT]) {
    for step in steps {
        stdin.write(&step.trustee_id);
        stdin.write(&step.derived_public_key);
        write_dleq_proof(stdin, &step.proof);
    }
}

fn write_decryption_steps(stdin: &mut SP1Stdin, steps: &[TrusteeDecryptionStep; TRUSTEE_COUNT]) {
    for step in steps {
        stdin.write(&step.trustee_id);
        stdin.write(&step.output_point);
        write_dleq_proof(stdin, &step.proof);
    }
}

fn aggregate_decryption_fixture() -> (AggregateDecryptionStatement, AggregateDecryptionWitness) {
    let (key_statement, key_setup_steps, factors) = trustee_fixtures();
    let program_id = key_statement.program_id;
    let pool_account = [0x22; 32];
    let auction_id = [0x23; 32];
    let funding_mint = key_statement.funding_mint;
    let confidential_vault = [0x25; 32];
    let key_epoch = key_statement.key_epoch;
    let trustee_ids = key_statement.trustee_ids;
    let verification_shares = key_statement.verification_shares;
    let bid_amounts = [100_000u64, 200_000u64];
    let low_openings = [Scalar::from(23u64), Scalar::from(29u64)];
    let high_openings = [Scalar::from(31u64), Scalar::from(37u64)];
    let public_key = CompressedRistretto(key_statement.auditor_pubkey)
        .decompress()
        .expect("fixture auditor key is valid");
    let h = CompressedRistretto(solana_pedersen_h())
        .decompress()
        .expect("Pedersen generator is valid");
    let encrypt = |amount: u64, opening: Scalar| {
        let commitment = (RISTRETTO_BASEPOINT_POINT * Scalar::from(amount) + h * opening)
            .compress()
            .to_bytes();
        let handle = (public_key * opening).compress().to_bytes();
        let mut ciphertext = [0; 64];
        ciphertext[..32].copy_from_slice(&commitment);
        ciphertext[32..].copy_from_slice(&handle);
        ciphertext
    };
    let low_ciphertexts = [
        encrypt(bid_amounts[0] & 0xffff, low_openings[0]),
        encrypt(bid_amounts[1] & 0xffff, low_openings[1]),
    ];
    let high_ciphertexts = [
        encrypt(bid_amounts[0] >> 16, high_openings[0]),
        encrypt(bid_amounts[1] >> 16, high_openings[1]),
    ];
    let aggregate_ciphertext_low =
        add_elgamal_ciphertexts(&low_ciphertexts[0], &low_ciphertexts[1])
            .expect("fixture low ciphertexts add");
    let aggregate_ciphertext_high =
        add_elgamal_ciphertexts(&high_ciphertexts[0], &high_ciphertexts[1])
            .expect("fixture high ciphertexts add");
    let mut funded_bid_commitments = [[0; 32]; MAX_FUNDED_BIDS];
    funded_bid_commitments[0] = [0x30; 32];
    funded_bid_commitments[1] = [0x31; 32];
    let mut accepted_transfer_context_hashes = [[0; 32]; MAX_FUNDED_BIDS];
    accepted_transfer_context_hashes[0] = [0x32; 32];
    accepted_transfer_context_hashes[1] = [0x33; 32];
    let statement = AggregateDecryptionStatement {
        program_id,
        pool_account,
        auction_id,
        funded_bid_root: funded_bid_merkle_root(&funded_bid_commitments),
        funding_mint,
        confidential_vault,
        auditor_pubkey: key_statement.auditor_pubkey,
        key_epoch,
        trustee_ids,
        verification_shares,
        funded_bid_count: 2,
        funded_bid_commitments,
        accepted_transfer_context_hashes,
        aggregate_ciphertext_low,
        aggregate_ciphertext_high,
        total_bid_amount: bid_amounts.iter().sum(),
    };
    let digest = statement.finalized_aggregate_digest();
    let make_steps = |ciphertext: &[u8; 64], component, nonces: [u64; TRUSTEE_COUNT]| {
        let mut current_handle: [u8; 32] = ciphertext[32..]
            .try_into()
            .expect("ciphertext handle is 32 bytes");
        std::array::from_fn(|index| {
            let trustee_index = u8::try_from(index + 1).expect("trustee index fits");
            let input = current_handle;
            current_handle = apply_decryption_factor(&input, &factors[index])
                .expect("fixture decryption transform is valid");
            let context = aggregate_decryption_context_hash(
                &program_id,
                &pool_account,
                &digest,
                &key_epoch,
                &trustee_ids[index],
                trustee_index,
                component,
            )
            .expect("fixture aggregate context is valid");
            let (_, proof) = prove_dleq_with_nonce(
                &factors[index],
                &Scalar::from(nonces[index]),
                context,
                input,
                current_handle,
            )
            .expect("fixture decryption DLEQ proof is valid");
            TrusteeDecryptionStep {
                trustee_id: trustee_ids[index],
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
            [53, 59, 61],
        ),
        high_steps: make_steps(
            &aggregate_ciphertext_high,
            AggregateComponent::High,
            [67, 71, 73],
        ),
        low_total: bid_amounts.iter().map(|amount| amount & 0xffff).sum(),
        high_total: bid_amounts.iter().map(|amount| amount >> 16).sum(),
    };
    (statement, witness)
}

fn aggregate_decryption_stdin_for(
    statement: &AggregateDecryptionStatement,
    witness: &AggregateDecryptionWitness,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&3u8);
    for field in [
        &statement.program_id,
        &statement.pool_account,
        &statement.auction_id,
        &statement.funded_bid_root,
        &statement.funding_mint,
        &statement.confidential_vault,
        &statement.auditor_pubkey,
        &statement.key_epoch,
    ] {
        stdin.write(field);
    }
    for trustee_id in &statement.trustee_ids {
        stdin.write(trustee_id);
    }
    for share in &statement.verification_shares {
        stdin.write(share);
    }
    stdin.write(&statement.funded_bid_count);
    for commitment in &statement.funded_bid_commitments {
        stdin.write(commitment);
    }
    for context_hash in &statement.accepted_transfer_context_hashes {
        stdin.write(context_hash);
    }
    for ciphertext in [
        &statement.aggregate_ciphertext_low,
        &statement.aggregate_ciphertext_high,
    ] {
        let commitment: [u8; 32] = ciphertext[..32]
            .try_into()
            .expect("ciphertext commitment is 32 bytes");
        let handle: [u8; 32] = ciphertext[32..]
            .try_into()
            .expect("ciphertext handle is 32 bytes");
        stdin.write(&commitment);
        stdin.write(&handle);
    }
    stdin.write(&statement.total_bid_amount);
    write_key_setup_steps(&mut stdin, &witness.key_setup_steps);
    write_decryption_steps(&mut stdin, &witness.low_steps);
    write_decryption_steps(&mut stdin, &witness.high_steps);
    stdin.write(&witness.low_total);
    stdin.write(&witness.high_total);
    stdin
}

fn execute(stdin: SP1Stdin) -> Result<(Vec<u8>, u64, u64), Box<dyn std::error::Error>> {
    let client = ProverClient::builder().light().build();
    let (public_values, report) = client.execute(FUNDING_GUEST_ELF, stdin).run()?;
    Ok((
        public_values.as_slice().to_vec(),
        report.total_instruction_count(),
        report.exit_code,
    ))
}

fn calculated_guest_vkey_hash() -> String {
    let client = ProverClient::builder().light().build();
    let proving_key = client
        .setup(FUNDING_GUEST_ELF)
        .expect("SP1 guest key setup must succeed");
    proving_key.verifying_key().bytes32()
}

fn guest_vkey_hash() -> String {
    let calculated = calculated_guest_vkey_hash();
    let checked_in = include_str!("../../../guest-vkey-hash.txt").trim();
    assert_eq!(
        calculated, checked_in,
        "guest ELF and on-chain verification-key hash are out of sync"
    );
    calculated
}

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None => run_fixtures(),
        Some("show-vkey") => {
            assert!(args.next().is_none(), "unexpected extra arguments");
            println!(
                "calculated guest verifier-key hash (not pin-checked): {}",
                calculated_guest_vkey_hash()
            );
        }
        Some("prove-claim") => {
            let output_dir = args
                .next()
                .expect("usage: private-claims-proof-runner prove-claim <output-directory>");
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "local-prover")]
            generate_claim_proof(Path::new(&output_dir))
                .expect("local claim proof generation failed");
            #[cfg(not(feature = "local-prover"))]
            panic!("rebuild with --features local-prover to generate proofs");
        }
        Some("prove-funding") => {
            let output_dir = args
                .next()
                .expect("usage: private-claims-proof-runner prove-funding <output-directory>");
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "local-prover")]
            generate_funding_proof(Path::new(&output_dir))
                .expect("local funding proof generation failed");
            #[cfg(not(feature = "local-prover"))]
            panic!("rebuild with --features local-prover to generate proofs");
        }
        Some("prove-redemption") => {
            let output_dir = args
                .next()
                .expect("usage: private-claims-proof-runner prove-redemption <output-directory>");
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "local-prover")]
            generate_redemption_proof(Path::new(&output_dir))
                .expect("local redemption proof generation failed");
            #[cfg(not(feature = "local-prover"))]
            panic!("rebuild with --features local-prover to generate proofs");
        }
        Some("prove-aggregate-decryption-fixture") => {
            let output_dir = args.next().expect(
                "usage: private-claims-proof-runner prove-aggregate-decryption-fixture <output-directory>",
            );
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "local-prover")]
            generate_aggregate_decryption_proof(Path::new(&output_dir))
                .expect("local aggregate decryption proof generation failed");
            #[cfg(not(feature = "local-prover"))]
            panic!("rebuild with --features local-prover to generate proofs");
        }
        Some("prove-trustee-key-setup-fixture") => {
            let output_dir = args.next().expect(
                "usage: private-claims-proof-runner prove-trustee-key-setup-fixture <output-directory>",
            );
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "local-prover")]
            generate_trustee_key_setup_proof(Path::new(&output_dir))
                .expect("local trustee key setup proof generation failed");
            #[cfg(not(feature = "local-prover"))]
            panic!("rebuild with --features local-prover to generate proofs");
        }
        Some("check-network-signer") => {
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "network-prover")]
            check_network_signer().expect("SP1 network signer preflight failed");
            #[cfg(not(feature = "network-prover"))]
            panic!("rebuild with --features network-prover for SP1 network preflight");
        }
        Some("prove-aggregate-decryption-fixture-private-reserved") => {
            let output_dir = args.next().expect(
                "usage: private-claims-proof-runner prove-aggregate-decryption-fixture-private-reserved <output-directory>",
            );
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "network-prover")]
            generate_aggregate_decryption_network_proof(Path::new(&output_dir))
                .expect("private Reserved aggregate proof generation failed");
            #[cfg(not(feature = "network-prover"))]
            panic!("rebuild with --features network-prover to generate private proofs");
        }
        Some("prove-trustee-key-setup-fixture-private-reserved") => {
            let output_dir = args.next().expect(
                "usage: private-claims-proof-runner prove-trustee-key-setup-fixture-private-reserved <output-directory>",
            );
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "network-prover")]
            generate_trustee_key_setup_network_proof(Path::new(&output_dir))
                .expect("private Reserved trustee key setup proof generation failed");
            #[cfg(not(feature = "network-prover"))]
            panic!("rebuild with --features network-prover to generate private proofs");
        }
        Some(_) => panic!("usage: private-claims-proof-runner [show-vkey|check-network-signer|prove-funding|prove-claim|prove-redemption|prove-aggregate-decryption-fixture|prove-trustee-key-setup-fixture|prove-aggregate-decryption-fixture-private-reserved|prove-trustee-key-setup-fixture-private-reserved <output-directory>]"),
    }
}

fn run_fixtures() {
    println!("SP1 guest verification-key hash: {}", guest_vkey_hash());
    println!("deterministic aggregate and trustee-key fixtures are for local tests only");

    let (statement, witness) = fixture(123_456_789);
    let valid = execute(stdin_for(&statement, &witness)).expect("valid fixture must execute");
    assert_eq!(valid.2, 0, "valid fixture must exit successfully");
    assert_eq!(valid.0, statement.public_values());
    println!(
        "synthetic funding relation executed locally; public bytes={}, guest instructions={}",
        valid.0.len(),
        valid.1
    );

    let invalid_amount = FundingWitness {
        amount: witness.amount + 1,
        ..witness
    };
    let invalid_amount = execute(stdin_for(&statement, &invalid_amount))
        .expect("mutated amount must report an execution result");
    assert_ne!(invalid_amount.2, 0, "mutated amount must be rejected");

    let mut invalid_ciphertext = statement;
    invalid_ciphertext.ciphertext_low[0] ^= 1;
    let invalid_ciphertext = execute(stdin_for(&invalid_ciphertext, &witness))
        .expect("mutated ciphertext must report an execution result");
    assert_ne!(
        invalid_ciphertext.2, 0,
        "mutated ciphertext must be rejected"
    );
    println!("mutated amount and ciphertext rejected by local SP1 executor");

    let (claim_statement, claim_witness) = claim_fixture();
    assert!(verify_claim_relation(&claim_statement, &claim_witness));
    let claim = execute(claim_stdin_for(&claim_statement, &claim_witness))
        .expect("valid claim fixture must execute");
    assert_eq!(claim.2, 0, "valid claim fixture must exit successfully");
    assert_eq!(claim.0, claim_statement.public_values());
    println!(
        "synthetic claim relation executed locally; public bytes={}, guest instructions={}",
        claim.0.len(),
        claim.1
    );

    let mut invalid_claim_witness = claim_witness;
    invalid_claim_witness.bid_merkle_siblings[0][0] ^= 1;
    assert!(!verify_claim_relation(
        &claim_statement,
        &invalid_claim_witness
    ));
    let invalid_claim = execute(claim_stdin_for(&claim_statement, &invalid_claim_witness))
        .expect("mutated claim path must report an execution result");
    assert_ne!(
        invalid_claim.2, 0,
        "mutated claim path must be rejected by local SP1 executor"
    );
    println!("mutated claim Merkle path rejected by local SP1 executor");

    let (redemption_statement, redemption_witness) = redemption_fixture();
    assert!(verify_redemption_relation(
        &redemption_statement,
        &redemption_witness
    ));
    let redemption = execute(redemption_stdin_for(
        &redemption_statement,
        &redemption_witness,
    ))
    .expect("valid redemption fixture must execute");
    assert_eq!(redemption.2, 0, "valid redemption must exit successfully");
    assert_eq!(redemption.0, redemption_statement.public_values());
    println!(
        "synthetic redemption relation executed locally; public bytes={}, guest instructions={}",
        redemption.0.len(),
        redemption.1
    );

    let claim_nullifier = claim_nullifier(
        &redemption_statement.program_id,
        &redemption_statement.auction_id,
        &redemption_witness.bid_commitment,
        &redemption_witness.claim_secret,
    );
    let reused_claim_nullifier = RedemptionStatement {
        nullifier: claim_nullifier,
        ..redemption_statement
    };
    assert!(!verify_redemption_relation(
        &reused_claim_nullifier,
        &redemption_witness
    ));
    let reused_claim_nullifier_execution = execute(redemption_stdin_for(
        &reused_claim_nullifier,
        &redemption_witness,
    ))
    .expect("reused claim nullifier must report an execution result");
    assert_ne!(
        reused_claim_nullifier_execution.2, 0,
        "claim nullifier must not be reusable as a redemption nullifier"
    );
    println!("claim nullifier rejected as a redemption nullifier");

    let mut invalid_redemption_witness = redemption_witness;
    invalid_redemption_witness.note_merkle_siblings[0][0] ^= 1;
    assert!(!verify_redemption_relation(
        &redemption_statement,
        &invalid_redemption_witness
    ));
    let invalid_redemption = execute(redemption_stdin_for(
        &redemption_statement,
        &invalid_redemption_witness,
    ))
    .expect("mutated redemption path must report an execution result");
    assert_ne!(
        invalid_redemption.2, 0,
        "mutated redemption path must be rejected by local SP1 executor"
    );
    println!("mutated redemption Merkle path rejected by local SP1 executor");

    let (key_statement, key_steps, _) = trustee_fixtures();
    assert!(verify_trustee_key_setup_relation(
        &key_statement,
        &key_steps
    ));
    let key_setup = execute(trustee_key_setup_stdin_for(&key_statement, &key_steps))
        .expect("valid trustee key setup fixture must execute");
    assert_eq!(
        key_setup.2, 0,
        "valid key setup fixture must exit successfully"
    );
    assert_eq!(key_setup.0, key_statement.public_values());
    println!(
        "synthetic trustee key setup relation executed locally; public bytes={}, guest instructions={}",
        key_setup.0.len(),
        key_setup.1
    );

    let mut invalid_key_steps = key_steps;
    invalid_key_steps[0].trustee_id[0] ^= 1;
    assert!(!verify_trustee_key_setup_relation(
        &key_statement,
        &invalid_key_steps
    ));
    let invalid_key_setup = execute(trustee_key_setup_stdin_for(
        &key_statement,
        &invalid_key_steps,
    ))
    .expect("mutated key setup must report an execution result");
    assert_ne!(invalid_key_setup.2, 0, "mutated key setup must be rejected");
    println!("mutated trustee key setup transcript rejected by local SP1 executor");

    let (aggregate_statement, aggregate_witness) = aggregate_decryption_fixture();
    assert!(verify_aggregate_decryption_relation(
        &aggregate_statement,
        &aggregate_witness
    ));
    let aggregate = execute(aggregate_decryption_stdin_for(
        &aggregate_statement,
        &aggregate_witness,
    ))
    .expect("valid aggregate decryption fixture must execute");
    assert_eq!(
        aggregate.2, 0,
        "valid aggregate decryption fixture must exit successfully"
    );
    assert_eq!(aggregate.0, aggregate_statement.public_values());
    println!(
        "synthetic aggregate decryption relation executed locally; public bytes={}, guest instructions={}",
        aggregate.0.len(),
        aggregate.1
    );

    let mut invalid_aggregate_witness = aggregate_witness;
    invalid_aggregate_witness.high_steps[0].proof.response[0] ^= 1;
    assert!(!verify_aggregate_decryption_relation(
        &aggregate_statement,
        &invalid_aggregate_witness
    ));
    let invalid_aggregate = execute(aggregate_decryption_stdin_for(
        &aggregate_statement,
        &invalid_aggregate_witness,
    ))
    .expect("mutated aggregate transcript must report an execution result");
    assert_ne!(
        invalid_aggregate.2, 0,
        "mutated aggregate transcript must be rejected"
    );
    println!("mutated aggregate decryption transcript rejected by local SP1 executor");
}

#[cfg(feature = "local-prover")]
fn generate_aggregate_decryption_proof(
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = aggregate_decryption_fixture();
    generate_local_proof(
        aggregate_decryption_stdin_for(&statement, &witness),
        statement.public_values().to_vec(),
        output_dir,
        "synthetic-aggregate-decryption",
    )
}

#[cfg(feature = "local-prover")]
fn generate_trustee_key_setup_proof(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, steps, _) = trustee_fixtures();
    generate_local_proof(
        trustee_key_setup_stdin_for(&statement, &steps),
        statement.public_values().to_vec(),
        output_dir,
        "synthetic-trustee-key-setup",
    )
}

#[cfg(feature = "network-prover")]
fn generate_aggregate_decryption_network_proof(
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = aggregate_decryption_fixture();
    generate_private_reserved_proof(
        aggregate_decryption_stdin_for(&statement, &witness),
        statement.public_values().to_vec(),
        output_dir,
        "synthetic-aggregate-decryption",
    )
}

#[cfg(feature = "network-prover")]
fn generate_trustee_key_setup_network_proof(
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, steps, _) = trustee_fixtures();
    generate_private_reserved_proof(
        trustee_key_setup_stdin_for(&statement, &steps),
        statement.public_values().to_vec(),
        output_dir,
        "synthetic-trustee-key-setup",
    )
}

#[cfg(feature = "local-prover")]
fn generate_redemption_proof(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = redemption_fixture();
    generate_local_proof(
        redemption_stdin_for(&statement, &witness),
        statement.public_values().to_vec(),
        output_dir,
        "redemption",
    )
}

#[cfg(feature = "local-prover")]
fn generate_funding_proof(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = fixture(123_456_789);
    generate_local_proof(
        stdin_for(&statement, &witness),
        statement.public_values().to_vec(),
        output_dir,
        "funding",
    )
}

#[cfg(feature = "local-prover")]
fn generate_claim_proof(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = claim_fixture();
    generate_local_proof(
        claim_stdin_for(&statement, &witness),
        statement.public_values().to_vec(),
        output_dir,
        "claim",
    )
}

#[cfg(feature = "local-prover")]
fn generate_local_proof(
    stdin: SP1Stdin,
    public_values: Vec<u8>,
    output_dir: &Path,
    proof_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = ProverClient::builder().cpu().build();
    let proving_key = client.setup(FUNDING_GUEST_ELF)?;
    let guest_hash = proving_key.verifying_key().bytes32();
    let checked_in_hash = include_str!("../../../guest-vkey-hash.txt").trim();
    if guest_hash != checked_in_hash {
        return Err("guest ELF and checked-in verifier hash do not match".into());
    }

    let proof = client.prove(&proving_key, stdin).groth16().run()?;

    if proof.public_values.as_slice() != public_values {
        return Err("SP1 proof public values differ from the supplied statement".into());
    }
    client.verify(&proof, proving_key.verifying_key(), None)?;

    let proof_bytes = proof.bytes();
    if proof_bytes.len() != SP1_PROOF_LEN {
        return Err(format!(
            "SP1 Groth16 proof encoded to {} bytes, expected {}",
            proof_bytes.len(),
            SP1_PROOF_LEN
        )
        .into());
    }
    private_claims_onchain::verify_sp1_v6_proof_bytes(
        &proof_bytes,
        &public_values,
        checked_in_hash,
    )
    .map_err(|_| "on-chain SP1 verifier rejected the generated proof")?;

    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join(format!("{proof_name}.proof")), &proof_bytes)?;
    fs::write(
        output_dir.join(format!("{proof_name}.public-values")),
        &public_values,
    )?;
    println!(
        "generated and verified a synthetic {proof_name} Groth16 proof; proof_bytes={}, public_values_bytes={}, output_dir={}",
        proof_bytes.len(),
        public_values.len(),
        output_dir.display()
    );
    Ok(())
}

#[cfg(feature = "network-prover")]
fn check_network_signer() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = env::var("NETWORK_PRIVATE_KEY")
        .map_err(|_| std::io::Error::other("NETWORK_PRIVATE_KEY is missing"))?;
    sp1_sdk::network::signer::NetworkSigner::local(&private_key)
        .map_err(|_| std::io::Error::other("NETWORK_PRIVATE_KEY is invalid; value withheld"))?;
    println!("NETWORK_PRIVATE_KEY_FORMAT_OK");
    Ok(())
}

#[cfg(feature = "network-prover")]
fn request_id_summary(code: &str, request_id: &[u8]) -> String {
    if request_id.len() == 32 {
        format!("{code} request_id=0x{}", hex::encode(request_id))
    } else {
        format!("{code} request_id_present=true")
    }
}

#[cfg(feature = "network-prover")]
fn safe_network_error_summary(error: Option<&sp1_sdk::network::Error>) -> String {
    use sp1_sdk::network::Error as NetworkError;

    match error {
        Some(NetworkError::SimulationFailed) => "SP1_SIMULATION_FAILED".to_owned(),
        Some(NetworkError::RequestUnexecutable { request_id }) => {
            request_id_summary("SP1_REQUEST_UNEXECUTABLE", request_id)
        }
        Some(NetworkError::RequestUnfulfillable { request_id }) => {
            request_id_summary("SP1_REQUEST_UNFULFILLABLE", request_id)
        }
        Some(NetworkError::RequestReverted { request_id }) => {
            request_id_summary("SP1_REQUEST_REVERTED", request_id)
        }
        Some(NetworkError::RequestExpired { request_id }) => {
            request_id_summary("SP1_REQUEST_EXPIRED", request_id)
        }
        Some(NetworkError::RequestTimedOut { request_id }) => {
            request_id_summary("SP1_REQUEST_TIMED_OUT", request_id)
        }
        Some(NetworkError::RequestAuctionTimedOut { request_id }) => {
            request_id_summary("SP1_AUCTION_TIMED_OUT", request_id)
        }
        Some(NetworkError::RpcError(status)) => {
            format!("SP1_RPC_ERROR grpc_code={:?}", status.code())
        }
        Some(NetworkError::Other(_)) => "SP1_NETWORK_OTHER_ERROR".to_owned(),
        None => "SP1_ERROR_UNCLASSIFIED".to_owned(),
    }
}

#[cfg(feature = "network-prover")]
fn safe_network_failure(stage: &str, error: Option<&sp1_sdk::network::Error>) -> std::io::Error {
    std::io::Error::other(format!(
        "SP1_FAILURE stage={stage} {}",
        safe_network_error_summary(error)
    ))
}

#[cfg(feature = "network-prover")]
fn generate_private_reserved_proof(
    stdin: SP1Stdin,
    public_values: Vec<u8>,
    output_dir: &Path,
    proof_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use sp1_sdk::network::{FulfillmentStrategy, NetworkMode};
    use sp1_sdk::blocking::ProveRequest;

    check_network_signer()?;
    sp1_sdk::network::validation::validate_strategy_compatibility(
        NetworkMode::Reserved,
        FulfillmentStrategy::Reserved,
    )
    .map_err(|_| std::io::Error::other("SP1_STRATEGY_CONFIGURATION_INVALID"))?;

    fs::create_dir_all(output_dir)?;
    let client = ProverClient::builder()
        .network_for(NetworkMode::Reserved)
        .private()
        .build();
    let proving_key = client
        .setup(FUNDING_GUEST_ELF)
        .map_err(|_| std::io::Error::other("SP1_SETUP_FAILED"))?;
    let verifying_key = proving_key.verifying_key();
    let checked_in_hash = include_str!("../../../guest-vkey-hash.txt").trim();
    if verifying_key.bytes32() != checked_in_hash {
        return Err("guest ELF and checked-in verifier hash are out of sync".into());
    }

    eprintln!("SP1_PROGRESS=private_reserved_request_submit");
    let request_id = client
        .prove(&proving_key, stdin)
        .strategy(FulfillmentStrategy::Reserved)
        .private_stdin(true)
        .groth16()
        .request()
        .map_err(|error| {
            safe_network_failure(
                "private_reserved_submit",
                error.downcast_ref::<sp1_sdk::network::Error>(),
            )
        })?;
    let request_id_hex = format!("0x{}", hex::encode(request_id.as_slice()));
    eprintln!("SP1_REQUEST_ID={request_id_hex}");
    fs::write(
        output_dir.join(format!("{proof_name}.request-id")),
        request_id_hex.as_bytes(),
    )?;

    eprintln!("SP1_PROGRESS=waiting_for_private_reserved_proof");
    let proof = client.wait_proof(request_id, None, None).map_err(|error| {
        safe_network_failure(
            "private_reserved_wait",
            error.downcast_ref::<sp1_sdk::network::Error>(),
        )
    })?;
    eprintln!("SP1_PROGRESS=local_host_verification");
    if proof.public_values.as_slice() != public_values {
        return Err("SP1 proof public values differ from the supplied statement".into());
    }
    client
        .verify(&proof, verifying_key, None)
        .map_err(|_| std::io::Error::other("SP1_HOST_VERIFICATION_FAILED"))?;

    let proof_bytes = proof.bytes();
    if proof_bytes.len() != SP1_PROOF_LEN {
        return Err(format!(
            "SP1 Groth16 proof encoded to {} bytes, expected {}",
            proof_bytes.len(),
            SP1_PROOF_LEN
        )
        .into());
    }
    private_claims_onchain::verify_sp1_v6_proof_bytes(
        &proof_bytes,
        &public_values,
        checked_in_hash,
    )
    .map_err(|_| "on-chain SP1 verifier rejected the generated proof")?;

    fs::write(output_dir.join(format!("{proof_name}.proof")), &proof_bytes)?;
    fs::write(
        output_dir.join(format!("{proof_name}.public-values")),
        &public_values,
    )?;
    println!(
        "generated and verified a synthetic private Reserved {proof_name} Groth16 proof; proof_bytes={}, public_values_bytes={}, output_dir={}",
        proof_bytes.len(),
        public_values.len(),
        output_dir.display()
    );
    Ok(())
}
