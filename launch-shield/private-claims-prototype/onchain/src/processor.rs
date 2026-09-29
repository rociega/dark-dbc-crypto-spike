use crate::{
    dbc,
    instruction::{
        ClaimsInstruction, DECRYPTABLE_BALANCE_LEN, FUNDING_PUBLIC_VALUES_LEN,
    },
    sp1_v6,
    state::{ClaimPool, CLAIM_POOL_DATA_LEN, MAX_CLAIMS, MAX_FUNDED_BIDS},
};
use bytemuck::{bytes_of, try_pod_read_unaligned};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    hash::hashv,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    program_pack::Pack,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};
use spl_token::{
    instruction as token_instruction,
    state::{Account as TokenAccount, AccountState, Mint},
};
use spl_token_2022::extension::{
    confidential_transfer::{
        instruction as confidential_transfer_instruction, ConfidentialTransferAccount,
        ConfidentialTransferMint, DecryptableBalance, EncryptedBalance,
    },
    BaseStateWithExtensions, StateWithExtensions,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use std::convert::TryInto;

const AUCTION_ID_DOMAIN: &[u8] = b"private-claims:auction-id:test-v1";
const MAX_TOTAL_BID_AMOUNT: u64 = ((1u64 << 32) - 1) * MAX_CLAIMS as u64;
const INVALID_PROOF: ProgramError = ProgramError::Custom(2);
const INVALID_CONFIGURATION: ProgramError = ProgramError::Custom(3);
const INVALID_PUBLIC_VALUES: ProgramError = ProgramError::Custom(4);
const INVALID_TOKEN_ACCOUNTS: ProgramError = ProgramError::Custom(5);
const INVALID_CONFIDENTIAL_TRANSFER: ProgramError = ProgramError::Custom(6);
const INVALID_FUNDING_AUTHORITY: ProgramError = ProgramError::Custom(7);
// Do not enable funding or settlement until a reviewed proof binds the public
// aggregate to every accepted private bid.
const AGGREGATE_DECRYPTION_PROOF_READY: bool = false;

pub fn derive_auction_id(
    program_id: &Pubkey,
    authority: &Pubkey,
    nonce: &[u8; 32],
) -> [u8; 32] {
    hashv(&[
        AUCTION_ID_DOMAIN,
        program_id.as_ref(),
        authority.as_ref(),
        nonce,
    ])
    .to_bytes()
}

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> Result<(), ProgramError> {
    match ClaimsInstruction::unpack(instruction_data)? {
        ClaimsInstruction::Initialize {
            nonce,
            funding_mint,
            confidential_vault,
            output_mint,
            vault,
            total_bid_amount,
            total_output_amount,
        } => initialize(
            program_id,
            accounts,
            &nonce,
            &funding_mint,
            &confidential_vault,
            &output_mint,
            &vault,
            total_bid_amount,
            total_output_amount,
        ),
        ClaimsInstruction::FundBid {
            new_source_decryptable_balance,
            proof,
            public_values,
        } => fund_bid(
            program_id,
            accounts,
            new_source_decryptable_balance,
            proof,
            public_values,
        ),
        ClaimsInstruction::FinalizeFunding => finalize_funding(program_id, accounts),
        ClaimsInstruction::Settle => settle(program_id, accounts),
        ClaimsInstruction::RegisterClaim {
            proof,
            public_values,
        } => register_claim(program_id, accounts, proof, public_values),
        ClaimsInstruction::Redeem {
            proof,
            public_values,
        } => redeem(program_id, accounts, proof, public_values),
    }
}

fn initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    nonce: &[u8; 32],
    funding_mint_bytes: &[u8; 32],
    confidential_vault_bytes: &[u8; 32],
    output_mint_bytes: &[u8; 32],
    vault_bytes: &[u8; 32],
    total_bid_amount: u64,
    total_output_amount: u64,
) -> Result<(), ProgramError> {
    if accounts.len() != 11
        || total_bid_amount == 0
        || total_bid_amount > MAX_TOTAL_BID_AMOUNT
        || total_output_amount == 0
    {
        return Err(INVALID_CONFIGURATION);
    }
    let account_info_iter = &mut accounts.iter();
    let authority = next_account_info(account_info_iter)?;
    let pool_account = next_account_info(account_info_iter)?;
    let vault_authority = next_account_info(account_info_iter)?;
    let vault = next_account_info(account_info_iter)?;
    let output_mint = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;
    let funding_mint = next_account_info(account_info_iter)?;
    let confidential_vault = next_account_info(account_info_iter)?;
    let token_2022_program = next_account_info(account_info_iter)?;
    let system_program_account = next_account_info(account_info_iter)?;
    let confidential_vault_authority = next_account_info(account_info_iter)?;

    if !authority.is_signer || !authority.is_writable || !pool_account.is_writable {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if system_program_account.key != &system_program::id()
        || token_program.key != &spl_token::id()
        || !token_program.executable
        || output_mint.key.to_bytes() != *output_mint_bytes
        || vault.key.to_bytes() != *vault_bytes
        || output_mint.owner != &spl_token::id()
        || vault.owner != &spl_token::id()
        || funding_mint.key.to_bytes() != *funding_mint_bytes
        || confidential_vault.key.to_bytes() != *confidential_vault_bytes
        || funding_mint.owner != &spl_token_2022::id()
        || confidential_vault.owner != &spl_token_2022::id()
        || token_2022_program.key != &spl_token_2022::id()
        || !token_2022_program.executable
    {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }

    let auction_id = derive_auction_id(program_id, authority.key, nonce);
    let (expected_pool, pool_bump) =
        Pubkey::find_program_address(&[b"claim-pool", &auction_id], program_id);
    if pool_account.key != &expected_pool
        || pool_account.owner != &system_program::id()
        || !pool_account.data_is_empty()
    {
        return Err(ProgramError::InvalidAccountData);
    }

    let (expected_vault_authority, _vault_bump) =
        Pubkey::find_program_address(&[b"claim-vault", pool_account.key.as_ref()], program_id);
    if vault_authority.key != &expected_vault_authority {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }
    let (expected_confidential_vault_authority, confidential_vault_bump) =
        Pubkey::find_program_address(
            &[b"confidential-funding-vault", pool_account.key.as_ref()],
            program_id,
        );
    if confidential_vault_authority.key != &expected_confidential_vault_authority {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }
    let vault_state = TokenAccount::unpack(&vault.try_borrow_data()?)?;
    let _mint_state = Mint::unpack(&output_mint.try_borrow_data()?)?;
    if !safe_vault(&vault_state, output_mint.key, &expected_vault_authority) {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }
    let funding_mint_data = funding_mint.try_borrow_data()?;
    let funding_mint_state =
        StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&funding_mint_data)?;
    let confidential_mint_extension =
        funding_mint_state.get_extension::<ConfidentialTransferMint>()?;
    let auditor_pubkey = read_32(bytes_of(
        &confidential_mint_extension.auditor_elgamal_pubkey,
    ), 0)?;
    if auditor_pubkey == [0; 32] {
        return Err(INVALID_CONFIDENTIAL_TRANSFER);
    }

    let confidential_vault_data = confidential_vault.try_borrow_data()?;
    let confidential_vault_state =
        StateWithExtensions::<spl_token_2022::state::Account>::unpack(&confidential_vault_data)?;
    let confidential_vault_extension =
        confidential_vault_state.get_extension::<ConfidentialTransferAccount>()?;
    confidential_vault_extension.approved()?;
    let confidential_vault_elgamal_pubkey =
        read_32(bytes_of(&confidential_vault_extension.elgamal_pubkey), 0)?;
    if confidential_vault_state.base.mint != *funding_mint.key
        || confidential_vault_state.base.owner != expected_confidential_vault_authority
        || confidential_vault_elgamal_pubkey == [0; 32]
        || u64::from(confidential_vault_state.base.amount) != 0
        || u64::from(confidential_vault_extension.pending_balance_credit_counter) != 0
        || bytes_of(&confidential_vault_extension.available_balance)
            .iter()
            .any(|byte| *byte != 0)
        || bytes_of(&confidential_vault_extension.pending_balance_lo)
            .iter()
            .any(|byte| *byte != 0)
        || bytes_of(&confidential_vault_extension.pending_balance_hi)
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(INVALID_CONFIDENTIAL_TRANSFER);
    }
    drop(confidential_vault_state);
    drop(confidential_vault_data);
    drop(funding_mint_state);
    drop(funding_mint_data);

    create_pool_account(
        program_id,
        authority,
        pool_account,
        system_program_account,
        &auction_id,
        pool_bump,
    )?;

    let disable_confidential_credits =
        confidential_transfer_instruction::disable_confidential_credits(
            token_2022_program.key,
            confidential_vault.key,
            confidential_vault_authority.key,
            &[],
        )?;
    invoke_signed(
        &disable_confidential_credits,
        &[
            confidential_vault.clone(),
            confidential_vault_authority.clone(),
            token_2022_program.clone(),
        ],
        &[&[
            b"confidential-funding-vault",
            pool_account.key.as_ref(),
            &[confidential_vault_bump],
        ]],
    )?;
    let disable_non_confidential_credits =
        confidential_transfer_instruction::disable_non_confidential_credits(
            token_2022_program.key,
            confidential_vault.key,
            confidential_vault_authority.key,
            &[],
        )?;
    invoke_signed(
        &disable_non_confidential_credits,
        &[
            confidential_vault.clone(),
            confidential_vault_authority.clone(),
            token_2022_program.clone(),
        ],
        &[&[
            b"confidential-funding-vault",
            pool_account.key.as_ref(),
            &[confidential_vault_bump],
        ]],
    )?;

    let state = ClaimPool::new(
        authority.key.to_bytes(),
        auction_id,
        funding_mint.key.to_bytes(),
        confidential_vault.key.to_bytes(),
        auditor_pubkey,
        confidential_vault_elgamal_pubkey,
        output_mint.key.to_bytes(),
        vault.key.to_bytes(),
        total_bid_amount,
        total_output_amount,
    );
    state.pack(&mut pool_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn fund_bid(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_source_decryptable_balance_bytes: &[u8],
    proof: &[u8],
    public_values: &[u8],
) -> Result<(), ProgramError> {
    if !AGGREGATE_DECRYPTION_PROOF_READY {
        return Err(INVALID_CONFIGURATION);
    }
    if accounts.len() != 10
        || public_values.len() != FUNDING_PUBLIC_VALUES_LEN
        || new_source_decryptable_balance_bytes.len() != DECRYPTABLE_BALANCE_LEN
    {
        return Err(INVALID_PUBLIC_VALUES);
    }
    let account_info_iter = &mut accounts.iter();
    let pool_account = next_account_info(account_info_iter)?;
    let source = next_account_info(account_info_iter)?;
    let funding_mint = next_account_info(account_info_iter)?;
    let confidential_vault = next_account_info(account_info_iter)?;
    let authority = next_account_info(account_info_iter)?;
    let token_2022_program = next_account_info(account_info_iter)?;
    let equality_context = next_account_info(account_info_iter)?;
    let ciphertext_validity_context = next_account_info(account_info_iter)?;
    let range_context = next_account_info(account_info_iter)?;
    let confidential_vault_authority = next_account_info(account_info_iter)?;

    if !pool_account.is_writable || !source.is_writable || !confidential_vault.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if token_2022_program.key != &spl_token_2022::id()
        || !token_2022_program.executable
        || source.key == confidential_vault.key
        || funding_mint.owner != &spl_token_2022::id()
        || source.owner != &spl_token_2022::id()
        || confidential_vault.owner != &spl_token_2022::id()
        || equality_context.is_writable
        || ciphertext_validity_context.is_writable
        || range_context.is_writable
        || confidential_vault_authority.is_writable
    {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }

    let mut state = load_pool(program_id, pool_account)?;
    if state.funding_finalized
        || state.funded_bid_count as usize >= MAX_FUNDED_BIDS
        || funding_mint.key.to_bytes() != state.funding_mint
        || confidential_vault.key.to_bytes() != state.confidential_vault
        || !funding_public_values_match(program_id, &state, authority.key, public_values)
    {
        return Err(INVALID_PUBLIC_VALUES);
    }

    let (expected_confidential_vault_authority, confidential_vault_bump) =
        Pubkey::find_program_address(
        &[b"confidential-funding-vault", pool_account.key.as_ref()],
        program_id,
    );
    if confidential_vault_authority.key != &expected_confidential_vault_authority {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }
    let funding_mint_data = funding_mint.try_borrow_data()?;
    let funding_mint_state =
        StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&funding_mint_data)?;
    let confidential_mint_extension =
        funding_mint_state.get_extension::<ConfidentialTransferMint>()?;
    let auditor_pubkey = read_32(bytes_of(
        &confidential_mint_extension.auditor_elgamal_pubkey,
    ), 0)?;

    let source_data = source.try_borrow_data()?;
    let source_state = StateWithExtensions::<spl_token_2022::state::Account>::unpack(&source_data)?;
    let source_confidential_extension =
        source_state.get_extension::<ConfidentialTransferAccount>()?;
    source_confidential_extension.valid_as_source()?;

    let confidential_vault_data = confidential_vault.try_borrow_data()?;
    let confidential_vault_state =
        StateWithExtensions::<spl_token_2022::state::Account>::unpack(&confidential_vault_data)?;
    let confidential_vault_extension =
        confidential_vault_state.get_extension::<ConfidentialTransferAccount>()?;
    confidential_vault_extension.approved()?;
    let confidential_vault_elgamal_pubkey =
        read_32(bytes_of(&confidential_vault_extension.elgamal_pubkey), 0)?;

    if source_state.base.mint != *funding_mint.key
        || source_state.base.owner != *authority.key
        || source_state.base.delegate.is_some()
        || confidential_vault_state.base.mint != *funding_mint.key
        || confidential_vault_state.base.owner != expected_confidential_vault_authority
        || u64::from(confidential_vault_state.base.amount) != 0
        || auditor_pubkey != state.auditor_pubkey
        || confidential_vault_elgamal_pubkey != state.confidential_vault_elgamal_pubkey
        || auditor_pubkey == [0; 32]
        || bool::from(confidential_vault_extension.allow_confidential_credits)
        || u64::from(confidential_vault_extension.pending_balance_credit_counter) != 0
        || bytes_of(&confidential_vault_extension.pending_balance_lo)
            .iter()
            .any(|byte| *byte != 0)
        || bytes_of(&confidential_vault_extension.pending_balance_hi)
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(INVALID_CONFIDENTIAL_TRANSFER);
    }

    let equality_context_hash = hash_account_info(equality_context)?;
    let ciphertext_validity_context_hash = hash_account_info(ciphertext_validity_context)?;
    let range_context_hash = hash_account_info(range_context)?;
    let auditor_ciphertexts: &[u8; 128] = public_values
        .get(256..384)
        .ok_or(INVALID_PUBLIC_VALUES)?
        .try_into()
        .map_err(|_| INVALID_PUBLIC_VALUES)?;
    let program_id_bytes = program_id.to_bytes();
    let pool_key_bytes = pool_account.key.to_bytes();
    let source_key_bytes = source.key.to_bytes();
    let funding_mint_bytes = funding_mint.key.to_bytes();
    let confidential_vault_bytes = confidential_vault.key.to_bytes();
    let authority_bytes = authority.key.to_bytes();
    let transfer_context = private_claims_proof_relation::AcceptedTransferContext {
        program_id: &program_id_bytes,
        pool_account: &pool_key_bytes,
        source_account: &source_key_bytes,
        funding_mint: &funding_mint_bytes,
        confidential_vault: &confidential_vault_bytes,
        authority: &authority_bytes,
        auditor_pubkey: &state.auditor_pubkey,
        confidential_vault_elgamal_pubkey: &state.confidential_vault_elgamal_pubkey,
        new_source_decryptable_balance: new_source_decryptable_balance_bytes,
        auditor_ciphertexts,
        equality_context_hash: &equality_context_hash,
        ciphertext_validity_context_hash: &ciphertext_validity_context_hash,
        range_context_hash: &range_context_hash,
    };
    let transfer_context_hash = transfer_context.hash();
    if read_32(public_values, 192)? != transfer_context_hash {
        return Err(INVALID_PUBLIC_VALUES);
    }

    sp1_v6::verify_sp1_v6_proof(proof, public_values, guest_vkey_hash())
        .map_err(|_| INVALID_PROOF)?;

    let bid_commitment = read_32(public_values, 96)?;
    let new_source_decryptable_balance =
        try_pod_read_unaligned::<DecryptableBalance>(new_source_decryptable_balance_bytes)
            .map_err(|_| INVALID_CONFIDENTIAL_TRANSFER)?;
    let auditor_ciphertext_low =
        try_pod_read_unaligned::<EncryptedBalance>(&public_values[256..320])
            .map_err(|_| INVALID_PUBLIC_VALUES)?;
    let auditor_ciphertext_high =
        try_pod_read_unaligned::<EncryptedBalance>(&public_values[320..384])
            .map_err(|_| INVALID_PUBLIC_VALUES)?;

    drop(confidential_vault_state);
    drop(confidential_vault_data);
    drop(source_state);
    drop(source_data);
    drop(funding_mint_state);
    drop(funding_mint_data);

    let enable_confidential_credits =
        confidential_transfer_instruction::enable_confidential_credits(
            token_2022_program.key,
            confidential_vault.key,
            confidential_vault_authority.key,
            &[],
        )?;
    invoke_signed(
        &enable_confidential_credits,
        &[
            confidential_vault.clone(),
            confidential_vault_authority.clone(),
            token_2022_program.clone(),
        ],
        &[&[
            b"confidential-funding-vault",
            pool_account.key.as_ref(),
            &[confidential_vault_bump],
        ]],
    )?;

    let transfer_instruction = confidential_transfer_instruction::inner_transfer(
        token_2022_program.key,
        source.key,
        funding_mint.key,
        confidential_vault.key,
        &new_source_decryptable_balance,
        &auditor_ciphertext_low,
        &auditor_ciphertext_high,
        authority.key,
        &[],
        ProofLocation::ContextStateAccount(equality_context.key),
        ProofLocation::ContextStateAccount(ciphertext_validity_context.key),
        ProofLocation::ContextStateAccount(range_context.key),
    )?;
    invoke(
        &transfer_instruction,
        &[
            source.clone(),
            funding_mint.clone(),
            confidential_vault.clone(),
            equality_context.clone(),
            ciphertext_validity_context.clone(),
            range_context.clone(),
            authority.clone(),
            token_2022_program.clone(),
        ],
    )?;

    let pending_balance_credit_counter = {
        let confidential_vault_data = confidential_vault.try_borrow_data()?;
        let confidential_vault_state =
            StateWithExtensions::<spl_token_2022::state::Account>::unpack(
                &confidential_vault_data,
            )?;
        let confidential_vault_extension =
            confidential_vault_state.get_extension::<ConfidentialTransferAccount>()?;
        u64::from(confidential_vault_extension.pending_balance_credit_counter)
    };
    if pending_balance_credit_counter != 1 {
        return Err(INVALID_CONFIDENTIAL_TRANSFER);
    }
    let empty_decryptable_balance_bytes = [0u8; DECRYPTABLE_BALANCE_LEN];
    let empty_decryptable_balance =
        try_pod_read_unaligned::<DecryptableBalance>(&empty_decryptable_balance_bytes)
            .map_err(|_| INVALID_CONFIDENTIAL_TRANSFER)?;
    let apply_pending_balance =
        confidential_transfer_instruction::inner_apply_pending_balance(
            token_2022_program.key,
            confidential_vault.key,
            pending_balance_credit_counter,
            &empty_decryptable_balance,
            confidential_vault_authority.key,
            &[],
        )?;
    invoke_signed(
        &apply_pending_balance,
        &[
            confidential_vault.clone(),
            confidential_vault_authority.clone(),
            token_2022_program.clone(),
        ],
        &[&[
            b"confidential-funding-vault",
            pool_account.key.as_ref(),
            &[confidential_vault_bump],
        ]],
    )?;

    let disable_confidential_credits =
        confidential_transfer_instruction::disable_confidential_credits(
            token_2022_program.key,
            confidential_vault.key,
            confidential_vault_authority.key,
            &[],
        )?;
    invoke_signed(
        &disable_confidential_credits,
        &[
            confidential_vault.clone(),
            confidential_vault_authority.clone(),
            token_2022_program.clone(),
        ],
        &[&[
            b"confidential-funding-vault",
            pool_account.key.as_ref(),
            &[confidential_vault_bump],
        ]],
    )?;

    state.append_funded_bid(bid_commitment, transfer_context_hash)?;
    state.pack(&mut pool_account.try_borrow_mut_data()?)
}

fn finalize_funding(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> Result<(), ProgramError> {
    if accounts.len() != 2 {
        return Err(INVALID_CONFIGURATION);
    }
    let pool_account = &accounts[0];
    let authority = &accounts[1];
    if !pool_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut state = load_pool(program_id, pool_account)?;
    if authority.key.to_bytes() != state.authority {
        return Err(INVALID_FUNDING_AUTHORITY);
    }
    state.finalize_funding()?;
    state.pack(&mut pool_account.try_borrow_mut_data()?)
}

fn settle(program_id: &Pubkey, accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    if !AGGREGATE_DECRYPTION_PROOF_READY {
        return Err(INVALID_CONFIGURATION);
    }
    if accounts.len() != 19 {
        return Err(INVALID_CONFIGURATION);
    }
    let account_info_iter = &mut accounts.iter();
    let authority = next_account_info(account_info_iter)?;
    let pool_account = next_account_info(account_info_iter)?;
    let funding_mint = next_account_info(account_info_iter)?;
    let confidential_vault = next_account_info(account_info_iter)?;
    let confidential_vault_authority = next_account_info(account_info_iter)?;
    let output_mint = next_account_info(account_info_iter)?;
    let vault = next_account_info(account_info_iter)?;
    let dbc_config = next_account_info(account_info_iter)?;
    let dbc_pool = next_account_info(account_info_iter)?;
    let dbc_base_vault = next_account_info(account_info_iter)?;
    let dbc_quote_vault = next_account_info(account_info_iter)?;
    let token_2022_program = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;
    let equality_context = next_account_info(account_info_iter)?;
    let range_context = next_account_info(account_info_iter)?;
    let dbc_program = next_account_info(account_info_iter)?;
    let dbc_pool_authority = next_account_info(account_info_iter)?;
    let dbc_event_authority = next_account_info(account_info_iter)?;
    let instructions_sysvar = next_account_info(account_info_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.is_writable
        || !confidential_vault.is_writable
        || !confidential_vault_authority.is_writable
        || !vault.is_writable
        || !dbc_pool.is_writable
        || !dbc_base_vault.is_writable
        || !dbc_quote_vault.is_writable
        || equality_context.is_writable
        || range_context.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }

    if token_2022_program.key != &spl_token_2022::id()
        || !token_2022_program.executable
        || token_program.key != &spl_token::id()
        || !token_program.executable
        || dbc_program.key != &dbc::DBC_PROGRAM_ID
        || !dbc_program.executable
        || dbc_event_authority.key != &dbc::event_authority()
        || instructions_sysvar.key != &solana_program::sysvar::instructions::id()
        || funding_mint.owner != &spl_token_2022::id()
        || confidential_vault.owner != &spl_token_2022::id()
        || output_mint.owner != &spl_token::id()
        || vault.owner != &spl_token::id()
        || dbc_config.owner != &dbc::DBC_PROGRAM_ID
        || dbc_pool.owner != &dbc::DBC_PROGRAM_ID
        || dbc_base_vault.owner != &spl_token::id()
        || dbc_quote_vault.owner != &spl_token_2022::id()
    {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }

    let mut state = load_pool(program_id, pool_account)?;
    if authority.key.to_bytes() != state.authority
        || !state.funding_finalized
        || state.settled
        || state.funded_bid_count == 0
        || state.total_bid_amount == 0
        || state.total_bid_amount > MAX_TOTAL_BID_AMOUNT
        || state.total_output_amount == 0
        || funding_mint.key.to_bytes() != state.funding_mint
        || confidential_vault.key.to_bytes() != state.confidential_vault
        || output_mint.key.to_bytes() != state.output_mint
        || vault.key.to_bytes() != state.vault
    {
        return Err(INVALID_CONFIGURATION);
    }

    let (expected_confidential_vault_authority, confidential_vault_bump) =
        Pubkey::find_program_address(
            &[b"confidential-funding-vault", pool_account.key.as_ref()],
            program_id,
        );
    let (expected_claim_vault_authority, _) =
        Pubkey::find_program_address(&[b"claim-vault", pool_account.key.as_ref()], program_id);
    if confidential_vault_authority.key != &expected_confidential_vault_authority
        || dbc_pool.key
            != &dbc::pool_address(dbc_config.key, output_mint.key, funding_mint.key)
    {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }

    let funding_mint_data = funding_mint.try_borrow_data()?;
    let funding_mint_state =
        StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&funding_mint_data)?;
    let confidential_mint_extension =
        funding_mint_state.get_extension::<ConfidentialTransferMint>()?;
    let auditor_pubkey = read_32(bytes_of(
        &confidential_mint_extension.auditor_elgamal_pubkey,
    ), 0)?;
    if auditor_pubkey != state.auditor_pubkey {
        return Err(INVALID_CONFIDENTIAL_TRANSFER);
    }
    let funding_decimals = funding_mint_state.base.decimals;

    let confidential_vault_data = confidential_vault.try_borrow_data()?;
    let confidential_vault_state =
        StateWithExtensions::<spl_token_2022::state::Account>::unpack(&confidential_vault_data)?;
    let confidential_vault_extension =
        confidential_vault_state.get_extension::<ConfidentialTransferAccount>()?;
    confidential_vault_extension.approved()?;
    confidential_vault_extension.valid_as_source()?;
    let confidential_vault_elgamal_pubkey =
        read_32(bytes_of(&confidential_vault_extension.elgamal_pubkey), 0)?;
    if confidential_vault_state.base.mint != *funding_mint.key
        || confidential_vault_state.base.owner != expected_confidential_vault_authority
        || confidential_vault_elgamal_pubkey != state.confidential_vault_elgamal_pubkey
        || u64::from(confidential_vault_state.base.amount) != 0
        || bool::from(confidential_vault_extension.allow_confidential_credits)
        || bool::from(confidential_vault_extension.allow_non_confidential_credits)
        || u64::from(confidential_vault_extension.pending_balance_credit_counter) != 0
        || bytes_of(&confidential_vault_extension.pending_balance_lo)
            .iter()
            .any(|byte| *byte != 0)
        || bytes_of(&confidential_vault_extension.pending_balance_hi)
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(INVALID_CONFIDENTIAL_TRANSFER);
    }

    let dbc_base_vault_state = TokenAccount::unpack(&dbc_base_vault.try_borrow_data()?)?;
    let dbc_quote_vault_data = dbc_quote_vault.try_borrow_data()?;
    let dbc_quote_vault_state =
        StateWithExtensions::<spl_token_2022::state::Account>::unpack(&dbc_quote_vault_data)?;
    if dbc_base_vault_state.mint != *output_mint.key
        || dbc_base_vault_state.state != AccountState::Initialized
        || dbc_quote_vault_state.base.mint != *funding_mint.key
        || dbc_quote_vault_state.base.state != spl_token_2022::state::AccountState::Initialized
    {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }
    let output_vault_state = TokenAccount::unpack(&vault.try_borrow_data()?)?;
    if !safe_vault(
        &output_vault_state,
        output_mint.key,
        &expected_claim_vault_authority,
    ) {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }
    let output_balance_before = output_vault_state.amount;
    drop(dbc_quote_vault_state);
    drop(dbc_quote_vault_data);
    drop(confidential_vault_state);
    drop(confidential_vault_data);
    drop(funding_mint_state);
    drop(funding_mint_data);

    let empty_decryptable_balance_bytes = [0u8; DECRYPTABLE_BALANCE_LEN];
    let empty_decryptable_balance =
        try_pod_read_unaligned::<DecryptableBalance>(&empty_decryptable_balance_bytes)
            .map_err(|_| INVALID_CONFIDENTIAL_TRANSFER)?;
    let withdraw_instruction = confidential_transfer_instruction::inner_withdraw(
        token_2022_program.key,
        confidential_vault.key,
        funding_mint.key,
        state.total_bid_amount,
        funding_decimals,
        &empty_decryptable_balance,
        confidential_vault_authority.key,
        &[],
        ProofLocation::ContextStateAccount(equality_context.key),
        ProofLocation::ContextStateAccount(range_context.key),
    )?;
    invoke_signed(
        &withdraw_instruction,
        &[
            confidential_vault.clone(),
            funding_mint.clone(),
            equality_context.clone(),
            range_context.clone(),
            confidential_vault_authority.clone(),
            token_2022_program.clone(),
        ],
        &[&[
            b"confidential-funding-vault",
            pool_account.key.as_ref(),
            &[confidential_vault_bump],
        ]],
    )?;

    let input_after_withdraw = {
        let confidential_vault_data = confidential_vault.try_borrow_data()?;
        let confidential_vault_state =
            StateWithExtensions::<spl_token_2022::state::Account>::unpack(
                &confidential_vault_data,
            )?;
        u64::from(confidential_vault_state.base.amount)
    };
    if input_after_withdraw != state.total_bid_amount {
        return Err(INVALID_CONFIDENTIAL_TRANSFER);
    }

    let swap_instruction = dbc::swap2_instruction(
        instructions_sysvar.key,
        dbc_pool_authority.key,
        dbc_config.key,
        dbc_pool.key,
        confidential_vault.key,
        vault.key,
        dbc_base_vault.key,
        dbc_quote_vault.key,
        output_mint.key,
        funding_mint.key,
        confidential_vault_authority.key,
        token_program.key,
        token_2022_program.key,
        state.total_bid_amount,
        state.total_output_amount,
    );
    invoke_signed(
        &swap_instruction,
        &[
            dbc_pool_authority.clone(),
            dbc_config.clone(),
            dbc_pool.clone(),
            confidential_vault.clone(),
            vault.clone(),
            dbc_base_vault.clone(),
            dbc_quote_vault.clone(),
            output_mint.clone(),
            funding_mint.clone(),
            confidential_vault_authority.clone(),
            token_program.clone(),
            token_2022_program.clone(),
            dbc_program.clone(),
            dbc_event_authority.clone(),
            dbc_program.clone(),
            instructions_sysvar.clone(),
            dbc_program.clone(),
        ],
        &[&[
            b"confidential-funding-vault",
            pool_account.key.as_ref(),
            &[confidential_vault_bump],
        ]],
    )?;

    let input_after_swap = {
        let confidential_vault_data = confidential_vault.try_borrow_data()?;
        let confidential_vault_state =
            StateWithExtensions::<spl_token_2022::state::Account>::unpack(
                &confidential_vault_data,
            )?;
        u64::from(confidential_vault_state.base.amount)
    };
    if input_after_swap != 0 {
        return Err(INVALID_CONFIDENTIAL_TRANSFER);
    }
    let output_after = TokenAccount::unpack(&vault.try_borrow_data()?)?.amount;
    let actual_output = output_after
        .checked_sub(output_balance_before)
        .ok_or(INVALID_TOKEN_ACCOUNTS)?;
    if actual_output < state.total_output_amount {
        return Err(INVALID_CONFIGURATION);
    }
    state.finalize_settlement(actual_output)?;
    state.pack(&mut pool_account.try_borrow_mut_data()?)
}

fn register_claim(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: &[u8],
    public_values: &[u8],
) -> Result<(), ProgramError> {
    if accounts.len() != 1 || public_values.len() != 208 {
        return Err(INVALID_PUBLIC_VALUES);
    }
    let pool_account = &accounts[0];
    if !pool_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut state = load_pool(program_id, pool_account)?;
    if !claim_public_values_match(program_id, &state, public_values) {
        return Err(INVALID_PUBLIC_VALUES);
    }
    sp1_v6::verify_sp1_v6_proof(proof, public_values, guest_vkey_hash())
        .map_err(|_| INVALID_PROOF)?;

    let note_commitment = read_32(public_values, 128)?;
    let claim_nullifier = read_32(public_values, 160)?;
    state.register_note(note_commitment, claim_nullifier)?;
    state.pack(&mut pool_account.try_borrow_mut_data()?)
}

fn redeem(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: &[u8],
    public_values: &[u8],
) -> Result<(), ProgramError> {
    if accounts.len() != 6 || public_values.len() != 200 {
        return Err(INVALID_PUBLIC_VALUES);
    }
    let account_info_iter = &mut accounts.iter();
    let pool_account = next_account_info(account_info_iter)?;
    let vault = next_account_info(account_info_iter)?;
    let vault_authority = next_account_info(account_info_iter)?;
    let destination = next_account_info(account_info_iter)?;
    let output_mint = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;
    if !pool_account.is_writable || !vault.is_writable || !destination.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut state = load_pool(program_id, pool_account)?;
    if !redemption_public_values_match(program_id, &state, public_values)
        || state.vault != vault.key.to_bytes()
        || state.output_mint != output_mint.key.to_bytes()
        || token_program.key != &spl_token::id()
        || destination.key.to_bytes() != read_32(public_values, 128)?
        || destination.key == vault.key
    {
        return Err(INVALID_PUBLIC_VALUES);
    }

    let (expected_vault_authority, vault_bump) =
        Pubkey::find_program_address(&[b"claim-vault", pool_account.key.as_ref()], program_id);
    if vault_authority.key != &expected_vault_authority
        || vault.owner != &spl_token::id()
        || output_mint.owner != &spl_token::id()
        || destination.owner != &spl_token::id()
    {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }
    let vault_state = TokenAccount::unpack(&vault.try_borrow_data()?)?;
    let destination_state = TokenAccount::unpack(&destination.try_borrow_data()?)?;
    let mint_state = Mint::unpack(&output_mint.try_borrow_data()?)?;
    if !safe_vault(&vault_state, output_mint.key, &expected_vault_authority)
        || destination_state.mint != *output_mint.key
        || destination_state.state != AccountState::Initialized
    {
        return Err(INVALID_TOKEN_ACCOUNTS);
    }

    sp1_v6::verify_sp1_v6_proof(proof, public_values, guest_vkey_hash())
        .map_err(|_| INVALID_PROOF)?;
    let redemption_nullifier = read_32(public_values, 160)?;
    let amount = read_u64(public_values, 192)?;
    if amount == 0 {
        return Err(INVALID_PUBLIC_VALUES);
    }
    state.mark_redemption_spent(redemption_nullifier)?;

    let transfer = token_instruction::transfer_checked(
        token_program.key,
        vault.key,
        output_mint.key,
        destination.key,
        vault_authority.key,
        &[],
        amount,
        mint_state.decimals,
    )?;
    invoke_signed(
        &transfer,
        &[
            vault.clone(),
            output_mint.clone(),
            destination.clone(),
            vault_authority.clone(),
            token_program.clone(),
        ],
        &[&[
            b"claim-vault",
            pool_account.key.as_ref(),
            &[vault_bump],
        ]],
    )?;

    state.pack(&mut pool_account.try_borrow_mut_data()?)
}

fn load_pool(program_id: &Pubkey, pool_account: &AccountInfo) -> Result<ClaimPool, ProgramError> {
    if pool_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    let state = ClaimPool::unpack(&pool_account.try_borrow_data()?)?;
    let (expected_pool, _) =
        Pubkey::find_program_address(&[b"claim-pool", &state.auction_id], program_id);
    if pool_account.key != &expected_pool {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(state)
}

fn create_pool_account<'a>(
    program_id: &Pubkey,
    authority: &AccountInfo<'a>,
    pool_account: &AccountInfo<'a>,
    system_program_account: &AccountInfo<'a>,
    auction_id: &[u8; 32],
    pool_bump: u8,
) -> Result<(), ProgramError> {
    let rent_minimum = Rent::get()?.minimum_balance(CLAIM_POOL_DATA_LEN);
    let signer_seeds: &[&[u8]] = &[b"claim-pool", auction_id, &[pool_bump]];
    if pool_account.lamports() == 0 {
        let create = system_instruction::create_account(
            authority.key,
            pool_account.key,
            rent_minimum,
            CLAIM_POOL_DATA_LEN as u64,
            program_id,
        );
        return invoke_signed(
            &create,
            &[
                authority.clone(),
                pool_account.clone(),
                system_program_account.clone(),
            ],
            &[signer_seeds],
        );
    }

    if pool_account.lamports() < rent_minimum {
        let top_up = system_instruction::transfer(
            authority.key,
            pool_account.key,
            rent_minimum - pool_account.lamports(),
        );
        invoke_signed(
            &top_up,
            &[
                authority.clone(),
                pool_account.clone(),
                system_program_account.clone(),
            ],
            &[signer_seeds],
        )?;
    }
    let allocate = system_instruction::allocate(pool_account.key, CLAIM_POOL_DATA_LEN as u64);
    invoke_signed(
        &allocate,
        &[pool_account.clone(), system_program_account.clone()],
        &[signer_seeds],
    )?;
    let assign = system_instruction::assign(pool_account.key, program_id);
    invoke_signed(
        &assign,
        &[pool_account.clone(), system_program_account.clone()],
        &[signer_seeds],
    )
}

fn claim_public_values_match(
    program_id: &Pubkey,
    state: &ClaimPool,
    public_values: &[u8],
) -> bool {
    state.funding_finalized
        && state.settled
        && state.funded_bid_count > 0
        && read_32(public_values, 0).ok() == Some(program_id.to_bytes())
        && read_32(public_values, 32).ok() == Some(state.auction_id)
        && read_32(public_values, 64).ok() == Some(state.funded_bid_root)
        && read_32(public_values, 96).ok() == Some(state.output_mint)
        && read_u64(public_values, 192).ok() == Some(state.total_bid_amount)
        && read_u64(public_values, 200).ok() == Some(state.total_output_amount)
}

fn redemption_public_values_match(
    program_id: &Pubkey,
    state: &ClaimPool,
    public_values: &[u8],
) -> bool {
    state.funding_finalized
        && state.settled
        && state.funded_bid_count > 0
        && read_32(public_values, 0).ok() == Some(program_id.to_bytes())
        && read_32(public_values, 32).ok() == Some(state.auction_id)
        && read_32(public_values, 64).ok() == Some(state.note_root())
        && read_32(public_values, 96).ok() == Some(state.output_mint)
}

fn funding_public_values_match(
    program_id: &Pubkey,
    state: &ClaimPool,
    bidder: &Pubkey,
    public_values: &[u8],
) -> bool {
    public_values.len() == FUNDING_PUBLIC_VALUES_LEN
        && read_32(public_values, 0).ok() == Some(program_id.to_bytes())
        && read_32(public_values, 32).ok() == Some(state.auction_id)
        && read_32(public_values, 64).ok() == Some(bidder.to_bytes())
        && read_32(public_values, 96)
            .map(|commitment| commitment != [0; 32])
            .unwrap_or(false)
        && read_32(public_values, 128).ok() == Some(state.funding_mint)
        && read_32(public_values, 160).ok() == Some(state.confidential_vault)
        && read_32(public_values, 224).ok() == Some(state.auditor_pubkey)
}

fn hash_account_info(account: &AccountInfo) -> Result<[u8; 32], ProgramError> {
    let data = account.try_borrow_data()?;
    let account_key = account.key.to_bytes();
    let owner = account.owner.to_bytes();
    Ok(private_claims_proof_relation::proof_context_account_hash(
        &account_key,
        &owner,
        data.as_ref(),
    ))
}

fn read_32(input: &[u8], offset: usize) -> Result<[u8; 32], ProgramError> {
    input
        .get(offset..offset + 32)
        .ok_or(INVALID_PUBLIC_VALUES)?
        .try_into()
        .map_err(|_| INVALID_PUBLIC_VALUES)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(
        input
            .get(offset..offset + 8)
            .ok_or(INVALID_PUBLIC_VALUES)?
            .try_into()
            .map_err(|_| INVALID_PUBLIC_VALUES)?,
    ))
}

fn safe_vault(vault: &TokenAccount, mint: &Pubkey, authority: &Pubkey) -> bool {
    vault.mint == *mint
        && vault.owner == *authority
        && vault.state == AccountState::Initialized
        && vault.delegate.is_none()
        && vault.delegated_amount == 0
        && vault.close_authority.is_none()
}

fn guest_vkey_hash() -> &'static str {
    include_str!("../../guest-vkey-hash.txt").trim()
}

#[cfg(test)]
mod tests {
    use super::{
        claim_public_values_match, derive_auction_id, redemption_public_values_match, safe_vault,
    };
    use crate::state::ClaimPool;
    use solana_program::{program_option::COption, pubkey::Pubkey};
    use spl_token::state::{Account as TokenAccount, AccountState};

    fn state() -> ClaimPool {
        let mut state = ClaimPool::new(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            [8; 32],
            100,
            1_000,
        );
        state.append_funded_bid([9; 32], [10; 32]).unwrap();
        state.finalize_funding().unwrap();
        state
            .finalize_settlement(state.total_output_amount)
            .unwrap();
        state
    }

    #[test]
    fn auction_id_is_stable_and_scoped_to_program_and_authority() {
        let program_id = Pubkey::new_from_array([9; 32]);
        let authority = Pubkey::new_from_array([10; 32]);
        let nonce = [11; 32];
        let auction_id = derive_auction_id(&program_id, &authority, &nonce);

        assert_eq!(auction_id, derive_auction_id(&program_id, &authority, &nonce));
        assert_ne!(
            auction_id,
            derive_auction_id(&program_id, &Pubkey::new_from_array([12; 32]), &nonce)
        );
    }

    #[test]
    fn funding_stays_fail_closed_until_aggregate_proof_is_ready() {
        let program_id = Pubkey::new_from_array([9; 32]);
        assert!(matches!(
            super::fund_bid(&program_id, &[], &[], &[], &[]),
            Err(solana_program::program_error::ProgramError::Custom(3))
        ));
    }

    #[test]
    fn settlement_stays_fail_closed_until_aggregate_proof_is_ready() {
        let program_id = Pubkey::new_from_array([9; 32]);
        assert!(matches!(
            super::settle(&program_id, &[]),
            Err(solana_program::program_error::ProgramError::Custom(3))
        ));
    }

    #[test]
    fn claim_statement_must_match_every_registered_auction_parameter() {
        let program_id = Pubkey::new_from_array([9; 32]);
        let state = state();
        let mut public_values = [0u8; 208];
        public_values[..32].copy_from_slice(program_id.as_ref());
        public_values[32..64].copy_from_slice(&state.auction_id);
        public_values[64..96].copy_from_slice(&state.funded_bid_root);
        public_values[96..128].copy_from_slice(&state.output_mint);
        public_values[192..200].copy_from_slice(&state.total_bid_amount.to_le_bytes());
        public_values[200..208].copy_from_slice(&state.total_output_amount.to_le_bytes());
        assert!(claim_public_values_match(
            &program_id,
            &state,
            &public_values
        ));

        public_values[64] ^= 1;
        assert!(!claim_public_values_match(
            &program_id,
            &state,
            &public_values
        ));
    }

    #[test]
    fn redemption_statement_must_use_the_current_root_and_asset() {
        let program_id = Pubkey::new_from_array([9; 32]);
        let state = state();
        let mut public_values = [0u8; 200];
        public_values[..32].copy_from_slice(program_id.as_ref());
        public_values[32..64].copy_from_slice(&state.auction_id);
        public_values[64..96].copy_from_slice(&state.note_root());
        public_values[96..128].copy_from_slice(&state.output_mint);
        assert!(redemption_public_values_match(
            &program_id,
            &state,
            &public_values
        ));

        public_values[64] ^= 1;
        assert!(!redemption_public_values_match(
            &program_id,
            &state,
            &public_values
        ));
    }

    #[test]
    fn vault_must_be_initialized_without_delegate_or_close_authority() {
        let mint = Pubkey::new_from_array([4; 32]);
        let authority = Pubkey::new_from_array([5; 32]);
        let mut vault = TokenAccount {
            mint,
            owner: authority,
            amount: 10_000,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        };
        assert!(safe_vault(&vault, &mint, &authority));

        vault.delegate = COption::Some(Pubkey::new_from_array([6; 32]));
        assert!(!safe_vault(&vault, &mint, &authority));
        vault.delegate = COption::None;
        vault.close_authority = COption::Some(Pubkey::new_from_array([7; 32]));
        assert!(!safe_vault(&vault, &mint, &authority));
        vault.close_authority = COption::None;
        vault.state = AccountState::Frozen;
        assert!(!safe_vault(&vault, &mint, &authority));
    }
}
