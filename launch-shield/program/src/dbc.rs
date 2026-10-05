use solana_program::{
    account_info::AccountInfo,
    hash::hash,
    instruction::Instruction,
    program_error::ProgramError,
    pubkey::{pubkey, Pubkey},
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};

use crate::error::{ShieldError, ShieldResult};

pub const DBC_PROGRAM_ID: Pubkey = pubkey!("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

const INIT_SPL_NAME: &[u8] = b"global:initialize_virtual_pool_with_spl_token";
const SWAP2_NAME: &[u8] = b"global:swap2";
const SWAP_NAME: &[u8] = b"global:swap";
const SWAP2_TRANSFER_HOOK_NAME: &[u8] = b"global:swap2_with_transfer_hook";
const SWAP2_ACCOUNT_COUNT: usize = 15;
const INIT_SPL_ACCOUNT_COUNT: usize = 16;
const TOKEN_METADATA_PROGRAM_ID: Pubkey = pubkey!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");

pub struct Swap2View {
    pub pool: Pubkey,
    pub input: Pubkey,
    pub output: Pubkey,
    pub payer: Pubkey,
    pub base_vault: Pubkey,
    pub quote_vault: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub token_base_program: Pubkey,
    pub token_quote_program: Pubkey,
    pub has_referral: bool,
    pub quote_amount: u64,
    pub min_output: u64,
}

pub fn pool_address(config: &Pubkey, base_mint: &Pubkey, quote_mint: &Pubkey) -> Pubkey {
    let (max_mint, min_mint) = if base_mint.to_bytes() > quote_mint.to_bytes() {
        (base_mint, quote_mint)
    } else {
        (quote_mint, base_mint)
    };
    Pubkey::find_program_address(
        &[
            b"pool",
            config.as_ref(),
            max_mint.as_ref(),
            min_mint.as_ref(),
        ],
        &DBC_PROGRAM_ID,
    )
    .0
}

pub fn verify_settlement_layout(
    instructions_sysvar: &AccountInfo,
    program_id: &Pubkey,
    auction_key: &Pubkey,
    creator: &Pubkey,
    dbc_config: &Pubkey,
    quote_mint: &Pubkey,
    base_mint: &Pubkey,
    expected_quote_amount: u64,
    required_min_output: u64,
    expected_input: &Pubkey,
    expected_output: &Pubkey,
) -> Result<Swap2View, ProgramError> {
    if instructions_sysvar.key != &solana_program::sysvar::instructions::id() {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }

    let current = load_current_index_checked(instructions_sysvar)? as usize;
    if current < 2 {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    let prepare_ix = load_instruction_at_checked(current, instructions_sysvar)?;
    if prepare_ix.program_id != *program_id
        || prepare_ix.data.as_slice() != [5]
        || prepare_ix.accounts.first().map(|meta| meta.pubkey) != Some(*auction_key)
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }

    let init_ix = load_instruction_at_checked(current - 2, instructions_sysvar)?;
    verify_init_instruction(&init_ix, dbc_config, quote_mint, base_mint, creator)?;

    let create_vault_ix = load_instruction_at_checked(current - 1, instructions_sysvar)?;
    verify_output_vault_creation(
        &create_vault_ix,
        expected_output,
        &vault_authority(program_id, auction_key).0,
        base_mint,
    )?;

    let swap_ix = load_instruction_at_checked(current + 1, instructions_sysvar)?;
    let swap = parse_swap2(&swap_ix)?;
    if swap.pool != pool_address(dbc_config, base_mint, quote_mint)
        || swap.base_mint != *base_mint
        || swap.quote_mint != *quote_mint
        || swap.quote_amount != expected_quote_amount
        || swap.min_output < required_min_output
        || swap.input != *expected_input
        || swap.output != *expected_output
        || swap.payer != *creator
        || swap.has_referral
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }

    let finalize_ix = load_instruction_at_checked(current + 2, instructions_sysvar)?;
    if finalize_ix.program_id != *program_id
        || finalize_ix.data.as_slice() != [6]
        || finalize_ix.accounts.first().map(|meta| meta.pubkey) != Some(*auction_key)
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }

    ensure_only_one_pool_swap(instructions_sysvar, &swap.pool, current + 1)?;

    Ok(Swap2View {
        pool: swap.pool,
        input: swap.input,
        output: swap.output,
        payer: swap.payer,
        base_vault: swap.base_vault,
        quote_vault: swap.quote_vault,
        base_mint: swap.base_mint,
        quote_mint: swap.quote_mint,
        token_base_program: swap.token_base_program,
        token_quote_program: swap.token_quote_program,
        has_referral: swap.has_referral,
        quote_amount: swap.quote_amount,
        min_output: swap.min_output,
    })
}

pub fn validate_finalize_predecessor(
    instructions_sysvar: &AccountInfo,
    program_id: &Pubkey,
    auction_key: &Pubkey,
    pool: &Pubkey,
    quote_amount: u64,
    min_output: u64,
    input: &Pubkey,
    output: &Pubkey,
    creator: &Pubkey,
) -> ShieldResult {
    if instructions_sysvar.key != &solana_program::sysvar::instructions::id() {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    let current = load_current_index_checked(instructions_sysvar)? as usize;
    if current < 1 {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    let finalize_ix = load_instruction_at_checked(current, instructions_sysvar)?;
    if finalize_ix.program_id != *program_id
        || finalize_ix.data.as_slice() != [6]
        || finalize_ix.accounts.first().map(|meta| meta.pubkey) != Some(*auction_key)
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    let swap_ix = load_instruction_at_checked(current - 1, instructions_sysvar)?;
    let swap = parse_swap2(&swap_ix)?;
    if swap.pool != *pool
        || swap.quote_amount != quote_amount
        || swap.min_output < min_output
        || swap.input != *input
        || swap.output != *output
        || swap.payer != *creator
        || swap.has_referral
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    Ok(())
}

pub fn parse_swap2(ix: &Instruction) -> Result<Swap2View, ProgramError> {
    if ix.program_id != DBC_PROGRAM_ID
        || ix.data.len() != 8 + 8 + 8 + 1
        || ix.data[..8] != discriminator(SWAP2_NAME)
        || ix.data[24] != 0
        || ix.accounts.len() != SWAP2_ACCOUNT_COUNT
        || ix.accounts[0].is_signer
        || ix.accounts[0].is_writable
        || ix.accounts[1].is_signer
        || ix.accounts[1].is_writable
        || (2..=6).any(|index| ix.accounts[index].is_signer || !ix.accounts[index].is_writable)
        || ix.accounts[7].is_signer
        || ix.accounts[7].is_writable
        || ix.accounts[8].is_signer
        || ix.accounts[8].is_writable
        || !ix.accounts[9].is_signer
        || !ix.accounts[9].is_writable
        || ix.accounts[10].is_signer
        || ix.accounts[10].is_writable
        || ix.accounts[11].is_signer
        || ix.accounts[11].is_writable
        || (ix.accounts[12].pubkey == DBC_PROGRAM_ID
            && (ix.accounts[12].is_signer || ix.accounts[12].is_writable))
        || ix.accounts[13].pubkey != swap2_event_authority()
        || ix.accounts[13].is_signer
        || ix.accounts[13].is_writable
        || ix.accounts[14].pubkey != DBC_PROGRAM_ID
        || ix.accounts[14].is_signer
        || ix.accounts[14].is_writable
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    let quote_amount = u64::from_le_bytes(
        ix.data[8..16]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    let min_output = u64::from_le_bytes(
        ix.data[16..24]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    if quote_amount == 0 || min_output == 0 {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    Ok(Swap2View {
        pool: ix.accounts[2].pubkey,
        input: ix.accounts[3].pubkey,
        output: ix.accounts[4].pubkey,
        payer: ix.accounts[9].pubkey,
        base_vault: ix.accounts[5].pubkey,
        quote_vault: ix.accounts[6].pubkey,
        base_mint: ix.accounts[7].pubkey,
        quote_mint: ix.accounts[8].pubkey,
        token_base_program: ix.accounts[10].pubkey,
        token_quote_program: ix.accounts[11].pubkey,
        has_referral: ix
            .accounts
            .get(12)
            .is_some_and(|meta| meta.pubkey != DBC_PROGRAM_ID),
        quote_amount,
        min_output,
    })
}

fn swap2_event_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"__event_authority"], &DBC_PROGRAM_ID).0
}

pub fn verify_init_instruction(
    ix: &Instruction,
    dbc_config: &Pubkey,
    quote_mint: &Pubkey,
    base_mint: &Pubkey,
    creator: &Pubkey,
) -> ShieldResult {
    if ix.program_id != DBC_PROGRAM_ID
        || ix.data.len() < 8
        || ix.data[..8] != discriminator(INIT_SPL_NAME)
        || ix.accounts.len() != INIT_SPL_ACCOUNT_COUNT
        || !meta_matches(&ix.accounts[0], dbc_config, true, true)
        || ix.accounts[1].is_signer
        || ix.accounts[1].is_writable
        || !meta_matches(&ix.accounts[2], creator, true, true)
        || !meta_matches(&ix.accounts[3], base_mint, true, true)
        || !meta_matches(&ix.accounts[4], quote_mint, false, false)
        || !meta_matches(
            &ix.accounts[5],
            &pool_address(dbc_config, base_mint, quote_mint),
            false,
            true,
        )
        || (6..=8).any(|index| ix.accounts[index].is_signer || !ix.accounts[index].is_writable)
        || !meta_matches(&ix.accounts[9], &TOKEN_METADATA_PROGRAM_ID, false, false)
        || !meta_matches(&ix.accounts[10], creator, true, true)
        || !meta_matches(&ix.accounts[11], &spl_token::id(), false, false)
        || !meta_matches(&ix.accounts[12], &spl_token::id(), false, false)
        || !meta_matches(
            &ix.accounts[13],
            &solana_program::system_program::id(),
            false,
            false,
        )
        || !meta_matches(&ix.accounts[14], &swap2_event_authority(), false, false)
        || !meta_matches(&ix.accounts[15], &DBC_PROGRAM_ID, false, false)
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    Ok(())
}

fn meta_matches(
    meta: &solana_program::instruction::AccountMeta,
    key: &Pubkey,
    is_signer: bool,
    is_writable: bool,
) -> bool {
    meta.pubkey == *key && meta.is_signer == is_signer && meta.is_writable == is_writable
}

fn verify_output_vault_creation(
    ix: &Instruction,
    output_vault: &Pubkey,
    authority: &Pubkey,
    base_mint: &Pubkey,
) -> ShieldResult {
    if ix.program_id != ASSOCIATED_TOKEN_PROGRAM_ID
        || ix.data.len() != 1
        || !matches!(ix.data[0], 0 | 1)
        || ix.accounts.len() < 6
        || ix.accounts[1].pubkey != *output_vault
        || ix.accounts[2].pubkey != *authority
        || ix.accounts[3].pubkey != *base_mint
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    Ok(())
}

fn ensure_only_one_pool_swap(
    instructions_sysvar: &AccountInfo,
    pool: &Pubkey,
    expected_index: usize,
) -> ShieldResult {
    let mut found = 0usize;
    let instruction_count = instruction_count_checked(instructions_sysvar)?;
    for index in 0..instruction_count {
        let ix = load_instruction_at_checked(index, instructions_sysvar)?;
        if ix.program_id != DBC_PROGRAM_ID || ix.data.len() < 8 {
            continue;
        }
        let disc = &ix.data[..8];
        let is_swap = disc == discriminator(SWAP_NAME)
            || disc == discriminator(SWAP2_NAME)
            || disc == discriminator(SWAP2_TRANSFER_HOOK_NAME);
        if is_swap
            && ix
                .accounts
                .get(2)
                .is_some_and(|account| account.pubkey == *pool)
        {
            found += 1;
            if index != expected_index {
                return Err(ShieldError::InvalidDbcInstruction.into());
            }
        }
    }
    if found != 1 {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    Ok(())
}

fn instruction_count_checked(instructions_sysvar: &AccountInfo) -> ShieldResult<usize> {
    if instructions_sysvar.key != &solana_program::sysvar::instructions::id() {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    let data = instructions_sysvar.try_borrow_data()?;
    instruction_count_from_data(&data)
}

fn instruction_count_from_data(data: &[u8]) -> ShieldResult<usize> {
    // The instructions sysvar begins with its top-level instruction count as a
    // little-endian u16, followed by the offset table and instruction records.
    let count_bytes = data.get(..2).ok_or(ShieldError::InvalidDbcInstruction)?;
    let count = usize::from(u16::from_le_bytes([count_bytes[0], count_bytes[1]]));
    let minimum_data_len = count
        .checked_mul(2)
        .and_then(|offsets_len| 2usize.checked_add(offsets_len))
        .and_then(|header_len| header_len.checked_add(2))
        .ok_or(ShieldError::InvalidDbcInstruction)?;
    if data.len() < minimum_data_len {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }
    Ok(count)
}

fn discriminator(name: &[u8]) -> [u8; 8] {
    let digest = hash(name).to_bytes();
    let mut output = [0u8; 8];
    output.copy_from_slice(&digest[..8]);
    output
}

pub fn vault_authority(program_id: &Pubkey, auction: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", auction.as_ref()], program_id)
}

pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), spl_token::id().as_ref(), mint.as_ref()],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    )
    .0
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::instruction::{AccountMeta, Instruction};

    fn swap2_fixture() -> Instruction {
        let mut accounts: Vec<AccountMeta> = (0..12)
            .map(|index| {
                let key = Pubkey::new_unique();
                if (2..=6).contains(&index) {
                    AccountMeta::new(key, false)
                } else if index == 9 {
                    AccountMeta::new(key, true)
                } else {
                    AccountMeta::new_readonly(key, false)
                }
            })
            .collect();
        accounts.push(AccountMeta::new_readonly(DBC_PROGRAM_ID, false));
        accounts.push(AccountMeta::new_readonly(swap2_event_authority(), false));
        accounts.push(AccountMeta::new_readonly(DBC_PROGRAM_ID, false));
        let mut data = discriminator(SWAP2_NAME).to_vec();
        data.extend_from_slice(&777u64.to_le_bytes());
        data.extend_from_slice(&555u64.to_le_bytes());
        data.push(0);
        Instruction {
            program_id: DBC_PROGRAM_ID,
            accounts,
            data,
        }
    }

    fn decode_base58(encoded: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut bytes = vec![0_u8];
        for character in encoded.bytes() {
            let value = ALPHABET
                .iter()
                .position(|candidate| *candidate == character)
                .unwrap() as u32;
            let mut carry = value;
            for byte in bytes.iter_mut().rev() {
                carry += u32::from(*byte) * 58;
                *byte = carry as u8;
                carry >>= 8;
            }
            while carry != 0 {
                bytes.insert(0, carry as u8);
                carry >>= 8;
            }
        }
        let leading_zeroes = encoded.bytes().take_while(|byte| *byte == b'1').count();
        let first_nonzero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        let mut decoded = vec![0; leading_zeroes];
        decoded.extend_from_slice(&bytes[first_nonzero..]);
        decoded
    }

    fn init_spl_fixture(
        config: Pubkey,
        creator: Pubkey,
        base_mint: Pubkey,
        quote_mint: Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: DBC_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(config, true),
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
                AccountMeta::new(creator, true),
                AccountMeta::new(base_mint, true),
                AccountMeta::new_readonly(quote_mint, false),
                AccountMeta::new(pool_address(&config, &base_mint, &quote_mint), false),
                AccountMeta::new(Pubkey::new_unique(), false),
                AccountMeta::new(Pubkey::new_unique(), false),
                AccountMeta::new(Pubkey::new_unique(), false),
                AccountMeta::new_readonly(TOKEN_METADATA_PROGRAM_ID, false),
                AccountMeta::new(creator, true),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
                AccountMeta::new_readonly(swap2_event_authority(), false),
                AccountMeta::new_readonly(DBC_PROGRAM_ID, false),
            ],
            data: discriminator(INIT_SPL_NAME).to_vec(),
        }
    }

    fn instructions_sysvar_data(instructions: &[Instruction], current_index: u16) -> Vec<u8> {
        let borrowed = instructions
            .iter()
            .map(
                |instruction| solana_program::sysvar::instructions::BorrowedInstruction {
                    program_id: &instruction.program_id,
                    accounts: instruction
                        .accounts
                        .iter()
                        .map(
                            |account| solana_program::sysvar::instructions::BorrowedAccountMeta {
                                pubkey: &account.pubkey,
                                is_signer: account.is_signer,
                                is_writable: account.is_writable,
                            },
                        )
                        .collect(),
                    data: &instruction.data,
                },
            )
            .collect::<Vec<_>>();
        #[allow(deprecated)]
        let mut data = solana_program::sysvar::instructions::construct_instructions_data(&borrowed);
        let current_index_offset = data.len() - 2;
        data[current_index_offset..].copy_from_slice(&current_index.to_le_bytes());
        data
    }

    fn with_instructions_sysvar<T>(
        instructions: &[Instruction],
        current_index: u16,
        run: impl FnOnce(&AccountInfo) -> T,
    ) -> T {
        let mut data = instructions_sysvar_data(instructions, current_index);
        let sysvar_key = solana_program::sysvar::instructions::id();
        let owner = Pubkey::default();
        let mut lamports = 1;
        let sysvar_info = AccountInfo::new(
            &sysvar_key,
            false,
            false,
            &mut lamports,
            &mut data,
            &owner,
            false,
            0,
        );
        run(&sysvar_info)
    }

    fn scan_pool_swaps(
        instructions: &[Instruction],
        pool: &Pubkey,
        expected_index: usize,
    ) -> ShieldResult {
        with_instructions_sysvar(instructions, 0, |sysvar_info| {
            ensure_only_one_pool_swap(sysvar_info, pool, expected_index)
        })
    }

    #[test]
    fn dbc_pool_pda_is_order_independent_for_mint_pair() {
        let config = Pubkey::new_unique();
        let base = Pubkey::new_unique();
        let quote = Pubkey::new_unique();
        assert_eq!(
            pool_address(&config, &base, &quote),
            pool_address(&config, &quote, &base)
        );
    }

    #[test]
    fn init_instruction_is_bound_to_program_config_creator_mints_and_pool() {
        let config = Pubkey::new_unique();
        let creator = Pubkey::new_unique();
        let base_mint = Pubkey::new_unique();
        let quote_mint = Pubkey::new_unique();
        let ix = init_spl_fixture(config, creator, base_mint, quote_mint);

        verify_init_instruction(&ix, &config, &quote_mint, &base_mint, &creator).unwrap();

        let mut wrong_program = ix.clone();
        wrong_program.program_id = Pubkey::new_unique();
        let mut wrong_discriminator = ix.clone();
        wrong_discriminator.data[0] ^= 1;
        let mut truncated_data = ix.clone();
        truncated_data.data.truncate(7);
        let mut wrong_config = ix.clone();
        wrong_config.accounts[0].pubkey = Pubkey::new_unique();
        let mut wrong_creator = ix.clone();
        wrong_creator.accounts[2].pubkey = Pubkey::new_unique();
        let mut wrong_base_mint = ix.clone();
        wrong_base_mint.accounts[3].pubkey = Pubkey::new_unique();
        let mut wrong_quote_mint = ix.clone();
        wrong_quote_mint.accounts[4].pubkey = Pubkey::new_unique();
        let mut wrong_pool = ix.clone();
        wrong_pool.accounts[5].pubkey = Pubkey::new_unique();
        let mut missing_pool = ix.clone();
        missing_pool.accounts.truncate(5);
        let mut missing_config_signature = ix.clone();
        missing_config_signature.accounts[0].is_signer = false;
        let mut wrong_metadata_program = ix.clone();
        wrong_metadata_program.accounts[9].pubkey = Pubkey::new_unique();
        let mut extra_account = ix.clone();
        extra_account
            .accounts
            .push(AccountMeta::new_readonly(Pubkey::new_unique(), false));

        for invalid in [
            wrong_program,
            wrong_discriminator,
            truncated_data,
            wrong_config,
            wrong_creator,
            wrong_base_mint,
            wrong_quote_mint,
            wrong_pool,
            missing_pool,
            missing_config_signature,
            wrong_metadata_program,
            extra_account,
        ] {
            assert!(
                verify_init_instruction(&invalid, &config, &quote_mint, &base_mint, &creator,)
                    .is_err()
            );
        }
    }

    #[test]
    fn recorded_devnet_initializer_matches_the_deployed_account_layout() {
        let config = solana_program::pubkey!("HhxjiR8GCW8eJt4jFwynM8UzJRyJerm6iJZHm6pbfzgF");
        let creator = solana_program::pubkey!("9TSdP6z2bPuZhwnZg9kZptjhFs6SBL7NzehZ1LLVdLAU");
        let base_mint = solana_program::pubkey!("29KUUA98TWEChS2eydAdYdje9fe4xWBEZ4XXbjuRCcCD");
        let quote_mint = solana_program::pubkey!("UNXUeg9TcH1SeL9tFnZH2jAWeXTnAee3mA8LVqvSyk7");
        let pool = solana_program::pubkey!("5octswXxT73dEQ8NqtBtSdgGer7Rzw5qYD3CnGm6gkuR");
        let mut ix = init_spl_fixture(config, creator, base_mint, quote_mint);
        ix.accounts[1].pubkey =
            solana_program::pubkey!("FhVo3mqL8PW5pH5U2CN4XE33DokiyZnUwuGpH2hmHLuM");
        ix.accounts[5].pubkey = pool;
        ix.accounts[6].pubkey =
            solana_program::pubkey!("8NYHeAM4uZ5iHCVQjQuZJS8EyLxF3R79RJ3hXWx6teh1");
        ix.accounts[7].pubkey =
            solana_program::pubkey!("3JtW9Kn95PxBErhTKfSo8SVqEm5ZEPhreUPo7NpazzJX");
        ix.accounts[8].pubkey =
            solana_program::pubkey!("8TdRQ5RFyyJe4je7GVz7VJLT2MxZcdaUGZMrrB4CAWSV");
        ix.data = decode_base58(
            "9ZsUZxnhjYMgBrc5JvfDyA6UMCQcrky9iCLXZW3Nwze5wek2u5FUoeo5LF5UJsev2eAFAfQg7SNaLLRFoVzAQuUKnrap4LfNTGwvZoFr7VN4jzksVJYpiE3Sf1ZFqnerau6T9Kqoa9GPpzvznRN4hJ79CRiwHJq5JwmUeJD2mCbZRd6i7XuxsHYP69495GtHYs1oQ8bbhRq3sDDBzzvb",
        );

        assert_eq!(ix.data.len(), 155);
        assert_eq!(ix.accounts.len(), INIT_SPL_ACCOUNT_COUNT);
        assert_eq!(pool, pool_address(&config, &base_mint, &quote_mint));
        verify_init_instruction(&ix, &config, &quote_mint, &base_mint, &creator).unwrap();
    }

    #[test]
    fn recorded_devnet_swap2_uses_fifteen_accounts_without_instructions_sysvar() {
        let expected = [
            "FhVo3mqL8PW5pH5U2CN4XE33DokiyZnUwuGpH2hmHLuM",
            "HhxjiR8GCW8eJt4jFwynM8UzJRyJerm6iJZHm6pbfzgF",
            "5octswXxT73dEQ8NqtBtSdgGer7Rzw5qYD3CnGm6gkuR",
            "4m11TgZLXwQeeDY1oBNTnLVHedF35kNaqyNY3J6ygepd",
            "BGEkWsngXdGDeYioRvMGdL5RA5aJKeHBkzPXbpdb21bx",
            "8NYHeAM4uZ5iHCVQjQuZJS8EyLxF3R79RJ3hXWx6teh1",
            "3JtW9Kn95PxBErhTKfSo8SVqEm5ZEPhreUPo7NpazzJX",
            "29KUUA98TWEChS2eydAdYdje9fe4xWBEZ4XXbjuRCcCD",
            "UNXUeg9TcH1SeL9tFnZH2jAWeXTnAee3mA8LVqvSyk7",
            "9TSdP6z2bPuZhwnZg9kZptjhFs6SBL7NzehZ1LLVdLAU",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN",
            "8Ks12pbrD6PXxfty1hVQiE9sc289zgU1zHkvXhrSdriF",
            "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN",
        ];
        let writable = [2, 3, 4, 5, 6, 9];
        let payer = solana_program::pubkey!("9TSdP6z2bPuZhwnZg9kZptjhFs6SBL7NzehZ1LLVdLAU");
        let accounts = expected
            .iter()
            .enumerate()
            .map(|(index, address)| {
                let key = address.parse::<Pubkey>().unwrap();
                if writable.contains(&index) {
                    AccountMeta::new(key, index == 9)
                } else {
                    AccountMeta::new_readonly(key, index == 9)
                }
            })
            .collect();
        let ix = Instruction {
            program_id: DBC_PROGRAM_ID,
            accounts,
            data: decode_base58("TGq5We4UqkvENK8uuXBSpTupJJeXgo7Vbm"),
        };

        let view = parse_swap2(&ix).unwrap();
        assert_eq!(
            view.pool,
            pool_address(
                &ix.accounts[1].pubkey,
                &ix.accounts[7].pubkey,
                &ix.accounts[8].pubkey
            )
        );
        assert_eq!(view.payer, payer);
        assert_eq!(view.quote_amount, 494_709_471);
        assert_eq!(view.min_output, 4_852_918);
        assert!(!view.has_referral);
        assert!(!ix
            .accounts
            .iter()
            .any(|meta| meta.pubkey == solana_program::sysvar::instructions::id()));
    }

    #[test]
    fn swap2_parser_requires_exact_in_and_reads_the_expected_accounts() {
        let mut ix = swap2_fixture();
        let pool = ix.accounts[2].pubkey;
        let input = ix.accounts[3].pubkey;
        let output = ix.accounts[4].pubkey;
        let base_vault = ix.accounts[5].pubkey;
        let quote_vault = ix.accounts[6].pubkey;
        let view = parse_swap2(&ix).unwrap();
        assert_eq!(view.pool, pool);
        assert_eq!(view.input, input);
        assert_eq!(view.output, output);
        assert_eq!(view.base_vault, base_vault);
        assert_eq!(view.quote_vault, quote_vault);
        assert_eq!(view.quote_amount, 777);
        assert_eq!(view.min_output, 555);
        assert!(!view.has_referral);

        ix.accounts[12].pubkey = Pubkey::new_unique();
        assert!(parse_swap2(&ix).unwrap().has_referral);

        ix.data[24] = 1;
        assert!(parse_swap2(&ix).is_err());
    }

    #[test]
    fn swap2_requires_the_observed_anchor_event_accounts_and_account_count() {
        let ix = swap2_fixture();
        assert!(!parse_swap2(&ix).unwrap().has_referral);

        let mut missing_account = swap2_fixture();
        missing_account.accounts.pop();
        assert!(parse_swap2(&missing_account).is_err());

        let mut wrong_event_authority = swap2_fixture();
        wrong_event_authority.accounts[13].pubkey = Pubkey::new_unique();
        assert!(parse_swap2(&wrong_event_authority).is_err());

        let mut wrong_program = swap2_fixture();
        wrong_program.accounts[14].pubkey = Pubkey::new_unique();
        assert!(parse_swap2(&wrong_program).is_err());

        let mut unsigned_payer = swap2_fixture();
        unsigned_payer.accounts[9].is_signer = false;
        assert!(parse_swap2(&unsigned_payer).is_err());

        let mut readonly_pool = swap2_fixture();
        readonly_pool.accounts[2].is_writable = false;
        assert!(parse_swap2(&readonly_pool).is_err());

        let mut extra_account = swap2_fixture();
        extra_account
            .accounts
            .push(AccountMeta::new_readonly(Pubkey::new_unique(), false));
        assert!(parse_swap2(&extra_account).is_err());
    }

    #[test]
    fn instruction_count_reads_the_sysvar_header_and_rejects_truncation() {
        let mut data = vec![0; 2 + 2 * 3 + 2];
        data[0] = 3;
        assert_eq!(instruction_count_from_data(&data).unwrap(), 3);
        assert!(instruction_count_from_data(&[3, 0]).is_err());
        assert_eq!(
            instruction_count_from_data(&[1]),
            Err(ShieldError::InvalidDbcInstruction.into())
        );
    }

    #[test]
    fn same_pool_swap_guard_scans_sysvar_instructions_and_rejects_duplicates() {
        let pool = Pubkey::new_unique();
        let mut expected_swap = swap2_fixture();
        expected_swap.accounts[2].pubkey = pool;
        let unrelated = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: Vec::new(),
            data: Vec::new(),
        };
        let instructions = vec![unrelated.clone(), expected_swap.clone(), unrelated.clone()];
        scan_pool_swaps(&instructions, &pool, 1).unwrap();

        let mut duplicate_swap = swap2_fixture();
        duplicate_swap.accounts[2].pubkey = pool;
        let duplicate_instructions = vec![expected_swap, unrelated, duplicate_swap];
        assert_eq!(
            scan_pool_swaps(&duplicate_instructions, &pool, 0),
            Err(ShieldError::InvalidDbcInstruction.into())
        );
    }

    #[test]
    fn settlement_layout_accepts_the_expected_five_instruction_sequence() {
        let program_id = Pubkey::new_unique();
        let auction = Pubkey::new_unique();
        let config = Pubkey::new_unique();
        let creator = Pubkey::new_unique();
        let quote_mint = Pubkey::new_unique();
        let base_mint = Pubkey::new_unique();
        let creator_input = Pubkey::new_unique();
        let base_output =
            associated_token_address(&vault_authority(&program_id, &auction).0, &base_mint);
        let pool = pool_address(&config, &base_mint, &quote_mint);
        let dbc_base_vault = Pubkey::new_unique();
        let dbc_quote_vault = Pubkey::new_unique();

        let init_ix = init_spl_fixture(config, creator, base_mint, quote_mint);
        let create_vault_ix = Instruction {
            program_id: ASSOCIATED_TOKEN_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(creator, true),
                AccountMeta::new(base_output, false),
                AccountMeta::new_readonly(vault_authority(&program_id, &auction).0, false),
                AccountMeta::new_readonly(base_mint, false),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: vec![1],
        };
        let prepare_ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(auction, false)],
            data: vec![5],
        };
        let mut swap_ix = swap2_fixture();
        swap_ix.accounts[2].pubkey = pool;
        swap_ix.accounts[3].pubkey = creator_input;
        swap_ix.accounts[4].pubkey = base_output;
        swap_ix.accounts[5].pubkey = dbc_base_vault;
        swap_ix.accounts[6].pubkey = dbc_quote_vault;
        swap_ix.accounts[7].pubkey = base_mint;
        swap_ix.accounts[8].pubkey = quote_mint;
        swap_ix.accounts[9].pubkey = creator;
        swap_ix.accounts[10].pubkey = spl_token::id();
        swap_ix.accounts[11].pubkey = spl_token::id();
        let finalize_ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(auction, false)],
            data: vec![6],
        };
        let instructions = vec![init_ix, create_vault_ix, prepare_ix, swap_ix, finalize_ix];

        with_instructions_sysvar(&instructions, 2, |instructions_sysvar| {
            let view = verify_settlement_layout(
                instructions_sysvar,
                &program_id,
                &auction,
                &creator,
                &config,
                &quote_mint,
                &base_mint,
                777,
                500,
                &creator_input,
                &base_output,
            )
            .unwrap();
            assert_eq!(view.pool, pool);
            assert_eq!(view.input, creator_input);
            assert_eq!(view.output, base_output);
            assert_eq!(view.quote_amount, 777);
            assert_eq!(view.min_output, 555);
        });
    }

    #[test]
    fn finalize_guard_binds_the_immediately_preceding_swap() {
        let program_id = Pubkey::new_unique();
        let auction = Pubkey::new_unique();
        let creator = Pubkey::new_unique();
        let pool = Pubkey::new_unique();
        let input = Pubkey::new_unique();
        let output = Pubkey::new_unique();
        let mut swap_ix = swap2_fixture();
        swap_ix.accounts[2].pubkey = pool;
        swap_ix.accounts[3].pubkey = input;
        swap_ix.accounts[4].pubkey = output;
        swap_ix.accounts[9].pubkey = creator;
        let finalize_ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(auction, false)],
            data: vec![6],
        };
        let validate = |instructions: &[Instruction]| {
            with_instructions_sysvar(instructions, 1, |instructions_sysvar| {
                validate_finalize_predecessor(
                    instructions_sysvar,
                    &program_id,
                    &auction,
                    &pool,
                    777,
                    500,
                    &input,
                    &output,
                    &creator,
                )
            })
        };

        let valid_instructions = vec![swap_ix.clone(), finalize_ix.clone()];
        validate(&valid_instructions).unwrap();

        let mut wrong_pool = swap_ix.clone();
        wrong_pool.accounts[2].pubkey = Pubkey::new_unique();
        let mut wrong_input = swap_ix.clone();
        wrong_input.accounts[3].pubkey = Pubkey::new_unique();
        let mut wrong_output = swap_ix.clone();
        wrong_output.accounts[4].pubkey = Pubkey::new_unique();
        let mut wrong_payer = swap_ix.clone();
        wrong_payer.accounts[9].pubkey = Pubkey::new_unique();
        let mut wrong_amount = swap_ix.clone();
        wrong_amount.data[8..16].copy_from_slice(&776u64.to_le_bytes());
        let mut insufficient_minimum = swap_ix.clone();
        insufficient_minimum.data[16..24].copy_from_slice(&499u64.to_le_bytes());
        let mut wrong_finalize = finalize_ix.clone();
        wrong_finalize.data[0] = 5;
        let wrong_predecessor = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(auction, false)],
            data: vec![5],
        };

        for instructions in [
            vec![wrong_pool, finalize_ix.clone()],
            vec![wrong_input, finalize_ix.clone()],
            vec![wrong_output, finalize_ix.clone()],
            vec![wrong_payer, finalize_ix.clone()],
            vec![wrong_amount, finalize_ix.clone()],
            vec![insufficient_minimum, finalize_ix.clone()],
            vec![swap_ix.clone(), wrong_finalize],
            vec![wrong_predecessor, finalize_ix],
        ] {
            assert_eq!(
                validate(&instructions),
                Err(ShieldError::InvalidDbcInstruction.into())
            );
        }

        swap_ix.data[16..24].copy_from_slice(&500u64.to_le_bytes());
        let exact_minimum_instructions = vec![
            swap_ix,
            Instruction {
                program_id,
                accounts: vec![AccountMeta::new(auction, false)],
                data: vec![6],
            },
        ];
        validate(&exact_minimum_instructions).unwrap();
    }
}
