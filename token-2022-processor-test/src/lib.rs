//! Lightweight Token-2022 processor, context-extraction, and CPI-builder checks.
//!
//! The mint test invokes the Token-2022 processor with in-memory AccountInfo
//! values and a host Rent syscall stub. Other tests inspect the CPI-compatible
//! instruction builder and call the transfer proof-context extractor with
//! in-memory context accounts generated from locally verified SDK proof data.
//! None executes the native Solana ProgramTest runtime, the proof program, an
//! actual CPI, or a confidential transfer.

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use solana_account_info::AccountInfo;
    use solana_pubkey::Pubkey;
    use solana_rent::Rent;
    use solana_sysvar::program_stubs::{self, SyscallStubs};
    use solana_zk_sdk::encryption::elgamal::{ElGamalPubkey, ElGamalSecretKey};
    use solana_zk_sdk_token::encryption::{
        elgamal::{
            ElGamalKeypair as TokenElGamalKeypair, ElGamalPubkey as TokenElGamalPubkey,
            ElGamalSecretKey as TokenElGamalSecretKey,
        },
        grouped_elgamal::GroupedElGamal,
        pedersen::{Pedersen, PedersenOpening},
        pod::elgamal::{PodElGamalCiphertext, PodElGamalPubkey as TokenPodElGamalPubkey},
    };
    use solana_zk_sdk_token::zk_elgamal_proof_program::{
        proof_data::{
            BatchedGroupedCiphertext3HandlesValidityProofContext,
            BatchedGroupedCiphertext3HandlesValidityProofData, BatchedRangeProofContext,
            BatchedRangeProofU128Data, CiphertextCommitmentEqualityProofContext,
            CiphertextCommitmentEqualityProofData, ZkProofData,
        },
        state::ProofContextState,
    };
    use spl_token_2022::extension::confidential_transfer::{
        DecryptableBalance, instruction::TransferInstructionData,
    };
    use spl_token_2022::{
        extension::{
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
            confidential_transfer::{
                ConfidentialTransferMint, instruction as confidential_transfer_instruction,
            },
        },
        instruction as token_instruction,
        processor::Processor,
        state::Mint,
    };
    use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
    use std::sync::Mutex;

    static SYSCALL_STUB_LOCK: Mutex<()> = Mutex::new(());

    struct RentSyscallStubs;

    impl SyscallStubs for RentSyscallStubs {
        fn sol_get_rent_sysvar(&self, _var_addr: *mut u8) -> u64 {
            0
        }
    }

    struct SyscallStubGuard(Option<Box<dyn SyscallStubs>>);

    impl Drop for SyscallStubGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                program_stubs::set_syscall_stubs(previous);
            }
        }
    }

    #[test]
    fn processor_initializes_mint_and_stores_sdk_compatible_auditor_key() {
        let secret = ElGamalSecretKey::from(Scalar::from(42_424_242u64));
        let sdk_pubkey = ElGamalPubkey::new(&secret);
        let serialized_pubkey = sdk_pubkey.get_point().compress().to_bytes();
        let token_pubkey = TokenElGamalPubkey::try_from(serialized_pubkey.as_slice())
            .expect("Token-2022 SDK must decode the current SDK key bytes");
        let auditor_key: TokenPodElGamalPubkey = token_pubkey.into();

        let token_program_id = spl_token_2022::id();
        let mint_key = Pubkey::new_unique();
        let authority_key = Pubkey::new_unique();
        let mint_extensions = [ExtensionType::ConfidentialTransferMint];
        let mint_len = ExtensionType::try_calculate_account_len::<Mint>(&mint_extensions).unwrap();
        let rent = Rent::default();
        let mut mint_lamports = rent.minimum_balance(mint_len);
        let mut mint_data = vec![0u8; mint_len];
        let mint_info = AccountInfo::new(
            &mint_key,
            false,
            true,
            &mut mint_lamports,
            &mut mint_data,
            &token_program_id,
            false,
            0,
        );

        let initialize_confidential_transfer = confidential_transfer_instruction::initialize_mint(
            &token_program_id,
            &mint_key,
            Some(authority_key),
            true,
            Some(auditor_key),
        )
        .unwrap();
        Processor::process(
            &token_program_id,
            &[mint_info.clone()],
            &initialize_confidential_transfer.data,
        )
        .expect("Token-2022 processor should initialize the confidential-transfer extension");

        let _syscall_lock = SYSCALL_STUB_LOCK.lock().unwrap();
        let _syscall_stub_guard = SyscallStubGuard(Some(program_stubs::set_syscall_stubs(
            Box::new(RentSyscallStubs),
        )));
        let initialize_base_mint = token_instruction::initialize_mint2(
            &token_program_id,
            &mint_key,
            &authority_key,
            None,
            6,
        )
        .unwrap();
        Processor::process(
            &token_program_id,
            &[mint_info.clone()],
            &initialize_base_mint.data,
        )
        .expect("Token-2022 processor should initialize the base mint");

        let mint_data = mint_info.data.borrow();
        let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data).unwrap();
        let confidential_transfer_mint = mint_state
            .get_extension::<ConfidentialTransferMint>()
            .unwrap();
        assert!(
            confidential_transfer_mint
                .auditor_elgamal_pubkey
                .equals(&auditor_key),
            "mint must retain the exact SDK-derived Pod auditor key"
        );
    }

    #[test]
    fn inner_transfer_cpi_builder_carries_exact_ciphertexts_and_context_accounts() {
        let token_program_id = spl_token_2022::id();
        let source = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let destination = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let equality_context = Pubkey::new_unique();
        let ciphertext_validity_context = Pubkey::new_unique();
        let range_context = Pubkey::new_unique();
        let auditor_secret = TokenElGamalSecretKey::from(Scalar::from(99_991u64));
        let auditor_pubkey = TokenElGamalPubkey::new(&auditor_secret);
        let auditor_ciphertext_lo: PodElGamalCiphertext = auditor_pubkey.encrypt_u64(0x1234).into();
        let auditor_ciphertext_hi: PodElGamalCiphertext = auditor_pubkey.encrypt_u64(0x5678).into();
        let new_source_balance = DecryptableBalance::default();

        let instruction = confidential_transfer_instruction::inner_transfer(
            &token_program_id,
            &source,
            &mint,
            &destination,
            &new_source_balance,
            &auditor_ciphertext_lo,
            &auditor_ciphertext_hi,
            &authority,
            &[],
            ProofLocation::ContextStateAccount(&equality_context),
            ProofLocation::ContextStateAccount(&ciphertext_validity_context),
            ProofLocation::ContextStateAccount(&range_context),
        )
        .expect("Token-2022 should construct its CPI-compatible transfer instruction");

        assert_eq!(instruction.accounts.len(), 7);
        assert_eq!(instruction.accounts[3].pubkey, equality_context);
        assert_eq!(instruction.accounts[4].pubkey, ciphertext_validity_context);
        assert_eq!(instruction.accounts[5].pubkey, range_context);
        assert!(instruction.accounts[6].is_signer);
        assert_eq!(
            instruction.data.len(),
            2 + std::mem::size_of::<TransferInstructionData>()
        );

        let transfer_data =
            bytemuck::pod_read_unaligned::<TransferInstructionData>(&instruction.data[2..]);
        assert_eq!(
            transfer_data.transfer_amount_auditor_ciphertext_lo,
            auditor_ciphertext_lo
        );
        assert_eq!(
            transfer_data.transfer_amount_auditor_ciphertext_hi,
            auditor_ciphertext_hi
        );
        assert_eq!(transfer_data.equality_proof_instruction_offset, 0);
        assert_eq!(
            transfer_data.ciphertext_validity_proof_instruction_offset,
            0
        );
        assert_eq!(transfer_data.range_proof_instruction_offset, 0);
    }

    #[test]
    fn token_2022_extracts_auditor_ciphertexts_from_context_state_accounts() {
        let source_keypair =
            TokenElGamalKeypair::new(TokenElGamalSecretKey::from(Scalar::from(11_111u64)));
        let destination_keypair =
            TokenElGamalKeypair::new(TokenElGamalSecretKey::from(Scalar::from(22_222u64)));
        let auditor_keypair =
            TokenElGamalKeypair::new(TokenElGamalSecretKey::from(Scalar::from(33_333u64)));

        let new_source_balance = 9_876u64;
        let new_source_opening = PedersenOpening::new(Scalar::from(44_444u64));
        let new_source_ciphertext = source_keypair
            .pubkey()
            .encrypt_with_u64(new_source_balance, &new_source_opening);
        let equality_proof = CiphertextCommitmentEqualityProofData::new(
            &source_keypair,
            &new_source_ciphertext,
            &new_source_ciphertext.commitment,
            &new_source_opening,
            new_source_balance,
        )
        .expect("generate source-balance equality proof");

        let amount_lo = 0x1234u64;
        let amount_hi = 0x5678u64;
        let opening_lo = PedersenOpening::new(Scalar::from(55_555u64));
        let opening_hi = PedersenOpening::new(Scalar::from(66_666u64));
        let grouped_ciphertext_lo = GroupedElGamal::<3>::encrypt_with(
            [
                source_keypair.pubkey(),
                destination_keypair.pubkey(),
                auditor_keypair.pubkey(),
            ],
            amount_lo,
            &opening_lo,
        );
        let grouped_ciphertext_hi = GroupedElGamal::<3>::encrypt_with(
            [
                source_keypair.pubkey(),
                destination_keypair.pubkey(),
                auditor_keypair.pubkey(),
            ],
            amount_hi,
            &opening_hi,
        );
        let validity_proof = BatchedGroupedCiphertext3HandlesValidityProofData::new(
            source_keypair.pubkey(),
            destination_keypair.pubkey(),
            auditor_keypair.pubkey(),
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        )
        .expect("generate grouped transfer-ciphertext validity proof");

        let padding_opening = PedersenOpening::new(Scalar::from(77_777u64));
        let padding_commitment = Pedersen::with(0u64, &padding_opening);
        let range_proof = BatchedRangeProofU128Data::new(
            vec![
                &new_source_ciphertext.commitment,
                &grouped_ciphertext_lo.commitment,
                &grouped_ciphertext_hi.commitment,
                &padding_commitment,
            ],
            vec![new_source_balance, amount_lo, amount_hi, 0],
            vec![64, 16, 32, 16],
            vec![
                &new_source_opening,
                &opening_lo,
                &opening_hi,
                &padding_opening,
            ],
        )
        .expect("generate bounded transfer-amount range proof");

        equality_proof
            .verify_proof()
            .expect("equality proof fixture must verify");
        validity_proof
            .verify_proof()
            .expect("ciphertext-validity proof fixture must verify");
        range_proof
            .verify_proof()
            .expect("range proof fixture must verify");

        let context_authority = Pubkey::new_unique();
        let equality_context_key = Pubkey::new_unique();
        let validity_context_key = Pubkey::new_unique();
        let range_context_key = Pubkey::new_unique();
        let proof_program_id = solana_zk_sdk_token::zk_elgamal_proof_program::id();

        let mut equality_lamports = 1;
        let mut equality_data =
            ProofContextState::<CiphertextCommitmentEqualityProofContext>::encode(
                &context_authority,
                CiphertextCommitmentEqualityProofData::PROOF_TYPE,
                equality_proof.context_data(),
            );
        let equality_account = AccountInfo::new(
            &equality_context_key,
            false,
            false,
            &mut equality_lamports,
            &mut equality_data,
            &proof_program_id,
            false,
            0,
        );

        let mut validity_lamports = 1;
        let mut validity_data =
            ProofContextState::<BatchedGroupedCiphertext3HandlesValidityProofContext>::encode(
                &context_authority,
                BatchedGroupedCiphertext3HandlesValidityProofData::PROOF_TYPE,
                validity_proof.context_data(),
            );
        let validity_account = AccountInfo::new(
            &validity_context_key,
            false,
            false,
            &mut validity_lamports,
            &mut validity_data,
            &proof_program_id,
            false,
            0,
        );

        let mut range_lamports = 1;
        let mut range_data = ProofContextState::<BatchedRangeProofContext>::encode(
            &context_authority,
            BatchedRangeProofU128Data::PROOF_TYPE,
            range_proof.context_data(),
        );
        let range_account = AccountInfo::new(
            &range_context_key,
            false,
            false,
            &mut range_lamports,
            &mut range_data,
            &proof_program_id,
            false,
            0,
        );

        let context_accounts = [equality_account, validity_account, range_account];
        let mut context_account_iter = context_accounts.iter();
        let transfer_context =
            spl_token_2022::extension::confidential_transfer::verify_proof::verify_transfer_proof(
                &mut context_account_iter,
                0,
                0,
                0,
            )
            .expect("Token-2022 should extract consistent proof contexts");

        let auditor_ciphertext_lo: PodElGamalCiphertext = grouped_ciphertext_lo
            .to_elgamal_ciphertext(2)
            .unwrap()
            .into();
        let auditor_ciphertext_hi: PodElGamalCiphertext = grouped_ciphertext_hi
            .to_elgamal_ciphertext(2)
            .unwrap()
            .into();
        assert_eq!(
            transfer_context
                .ciphertext_lo
                .try_extract_ciphertext(2)
                .unwrap(),
            auditor_ciphertext_lo
        );
        assert_eq!(
            transfer_context
                .ciphertext_hi
                .try_extract_ciphertext(2)
                .unwrap(),
            auditor_ciphertext_hi
        );
        let auditor_pubkey: TokenPodElGamalPubkey = (*auditor_keypair.pubkey()).into();
        assert_eq!(transfer_context.transfer_pubkeys.auditor, auditor_pubkey);
        assert_eq!(context_account_iter.count(), 0);

        let mut malformed_context = context_accounts[1].data.borrow_mut();
        malformed_context[std::mem::size_of::<Pubkey>()] = 0;
        drop(malformed_context);
        let mut malformed_context_iter = context_accounts.iter();
        assert!(
            spl_token_2022::extension::confidential_transfer::verify_proof::verify_transfer_proof(
                &mut malformed_context_iter,
                0,
                0,
                0,
            )
            .is_err(),
            "Token-2022 must reject a context account with the wrong proof type"
        );
    }
}
