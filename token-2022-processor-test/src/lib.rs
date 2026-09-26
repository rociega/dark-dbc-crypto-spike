//! Lightweight, direct-processor check for Token-2022 mint initialization.
//!
//! This invokes the Token-2022 processor with in-memory AccountInfo values. It
//! supplies Rent through a host syscall stub and avoids the native Solana
//! ProgramTest runtime. It does not validate actual runtime sysvar loading,
//! system-account creation, CPIs, or a confidential transfer.

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use solana_account_info::AccountInfo;
    use solana_pubkey::Pubkey;
    use solana_rent::Rent;
    use solana_sysvar::program_stubs::{self, SyscallStubs};
    use solana_zk_sdk::encryption::elgamal::{ElGamalPubkey, ElGamalSecretKey};
    use solana_zk_sdk_token::encryption::{
        elgamal::ElGamalPubkey as TokenElGamalPubkey,
        pod::elgamal::PodElGamalPubkey as TokenPodElGamalPubkey,
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
}
