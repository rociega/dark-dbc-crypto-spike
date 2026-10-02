use solana_program::{
    hash::hash,
    instruction::{AccountMeta, Instruction},
    pubkey::{pubkey, Pubkey},
};

pub const DBC_PROGRAM_ID: Pubkey = pubkey!("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");
const SWAP2_NAME: &[u8] = b"global:swap2";
const INITIALIZE_VIRTUAL_POOL_WITH_SPL_TOKEN_NAME: &[u8] =
    b"global:initialize_virtual_pool_with_spl_token";

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

pub fn event_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"__event_authority"], &DBC_PROGRAM_ID).0
}

#[allow(clippy::too_many_arguments)]
pub fn initialize_virtual_pool_with_spl_token_instruction(
    config: &Pubkey,
    pool_authority: &Pubkey,
    creator: &Pubkey,
    base_mint: &Pubkey,
    quote_mint: &Pubkey,
    pool: &Pubkey,
    base_vault: &Pubkey,
    quote_vault: &Pubkey,
    mint_metadata: &Pubkey,
    metadata_program: &Pubkey,
    payer: &Pubkey,
    token_quote_program: &Pubkey,
    token_program: &Pubkey,
    name: &str,
    symbol: &str,
    uri: &str,
    quote_token_badge: Option<Pubkey>,
) -> Instruction {
    let mut data = hash(INITIALIZE_VIRTUAL_POOL_WITH_SPL_TOKEN_NAME)
        .to_bytes()[..8]
        .to_vec();
    for value in [name, symbol, uri] {
        let value_len = u32::try_from(value.len()).expect("metadata string exceeds Borsh limit");
        data.extend_from_slice(&value_len.to_le_bytes());
        data.extend_from_slice(value.as_bytes());
    }

    let mut accounts = vec![
        AccountMeta::new_readonly(*config, false),
        AccountMeta::new_readonly(*pool_authority, false),
        AccountMeta::new_readonly(*creator, true),
        AccountMeta::new(*base_mint, true),
        AccountMeta::new_readonly(*quote_mint, false),
        AccountMeta::new(*pool, false),
        AccountMeta::new(*base_vault, false),
        AccountMeta::new(*quote_vault, false),
        AccountMeta::new(*mint_metadata, false),
        AccountMeta::new_readonly(*metadata_program, false),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(*token_quote_program, false),
        AccountMeta::new_readonly(*token_program, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
        AccountMeta::new_readonly(event_authority(), false),
        AccountMeta::new_readonly(DBC_PROGRAM_ID, false),
    ];
    if let Some(token_badge) = quote_token_badge {
        accounts.push(AccountMeta::new_readonly(token_badge, false));
    }

    Instruction {
        program_id: DBC_PROGRAM_ID,
        accounts,
        data,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn swap2_instruction(
    instructions_sysvar: &Pubkey,
    pool_authority: &Pubkey,
    config: &Pubkey,
    pool: &Pubkey,
    input: &Pubkey,
    output: &Pubkey,
    base_vault: &Pubkey,
    quote_vault: &Pubkey,
    base_mint: &Pubkey,
    quote_mint: &Pubkey,
    payer: &Pubkey,
    token_base_program: &Pubkey,
    token_quote_program: &Pubkey,
    amount_in: u64,
    minimum_amount_out: u64,
) -> Instruction {
    let mut data = hash(SWAP2_NAME).to_bytes()[..8].to_vec();
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_amount_out.to_le_bytes());
    data.push(0);

    Instruction {
        program_id: DBC_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(*pool_authority, false),
            AccountMeta::new_readonly(*config, false),
            AccountMeta::new(*pool, false),
            AccountMeta::new(*input, false),
            AccountMeta::new(*output, false),
            AccountMeta::new(*base_vault, false),
            AccountMeta::new(*quote_vault, false),
            AccountMeta::new_readonly(*base_mint, false),
            AccountMeta::new_readonly(*quote_mint, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*token_base_program, false),
            AccountMeta::new_readonly(*token_quote_program, false),
            AccountMeta::new_readonly(DBC_PROGRAM_ID, false),
            AccountMeta::new_readonly(event_authority(), false),
            AccountMeta::new_readonly(DBC_PROGRAM_ID, false),
            AccountMeta::new_readonly(*instructions_sysvar, false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::sysvar::instructions;

    #[test]
    fn spl_pool_initializer_matches_pinned_anchor_account_and_borsh_layout() {
        let config = Pubkey::new_unique();
        let pool_authority = Pubkey::new_unique();
        let creator = Pubkey::new_unique();
        let base_mint = Pubkey::new_unique();
        let quote_mint = Pubkey::new_unique();
        let pool = Pubkey::new_unique();
        let base_vault = Pubkey::new_unique();
        let quote_vault = Pubkey::new_unique();
        let mint_metadata = Pubkey::new_unique();
        let metadata_program = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let token_quote_program = Pubkey::new_unique();
        let token_program = Pubkey::new_unique();
        let quote_token_badge = Pubkey::new_unique();
        let name = "Shield Test";
        let symbol = "SHLD";
        let uri = "https://example.invalid/token.json";

        let instruction = initialize_virtual_pool_with_spl_token_instruction(
            &config,
            &pool_authority,
            &creator,
            &base_mint,
            &quote_mint,
            &pool,
            &base_vault,
            &quote_vault,
            &mint_metadata,
            &metadata_program,
            &payer,
            &token_quote_program,
            &token_program,
            name,
            symbol,
            uri,
            Some(quote_token_badge),
        );

        assert_eq!(instruction.program_id, DBC_PROGRAM_ID);
        assert_eq!(
            &instruction.data[..8],
            &[0x8c, 0x55, 0xd7, 0xb0, 0x66, 0x36, 0x68, 0x4f]
        );
        let mut expected_data = vec![0x8c, 0x55, 0xd7, 0xb0, 0x66, 0x36, 0x68, 0x4f];
        for value in [name, symbol, uri] {
            expected_data.extend_from_slice(&(value.len() as u32).to_le_bytes());
            expected_data.extend_from_slice(value.as_bytes());
        }
        assert_eq!(instruction.data, expected_data);

        let expected_accounts = [
            config,
            pool_authority,
            creator,
            base_mint,
            quote_mint,
            pool,
            base_vault,
            quote_vault,
            mint_metadata,
            metadata_program,
            payer,
            token_quote_program,
            token_program,
            solana_program::system_program::id(),
            event_authority(),
            DBC_PROGRAM_ID,
            quote_token_badge,
        ];
        assert_eq!(instruction.accounts.len(), expected_accounts.len());
        for (index, (account, expected_key)) in instruction
            .accounts
            .iter()
            .zip(expected_accounts)
            .enumerate()
        {
            assert_eq!(account.pubkey, expected_key);
            assert_eq!(account.is_signer, matches!(index, 2 | 3 | 10));
            assert_eq!(account.is_writable, matches!(index, 3 | 5 | 6 | 7 | 8 | 10));
        }
    }

    #[test]
    fn swap2_instruction_matches_the_pinned_anchor_account_and_data_layout() {
        let instructions_sysvar = instructions::id();
        let pool_authority = Pubkey::new_unique();
        let config = Pubkey::new_unique();
        let pool = Pubkey::new_unique();
        let input = Pubkey::new_unique();
        let output = Pubkey::new_unique();
        let base_vault = Pubkey::new_unique();
        let quote_vault = Pubkey::new_unique();
        let base_mint = Pubkey::new_unique();
        let quote_mint = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let token_base_program = Pubkey::new_unique();
        let token_quote_program = Pubkey::new_unique();
        let amount_in = 0x0102_0304_0506_0708;
        let minimum_amount_out = 0x1112_1314_1516_1718;

        let instruction = swap2_instruction(
            &instructions_sysvar,
            &pool_authority,
            &config,
            &pool,
            &input,
            &output,
            &base_vault,
            &quote_vault,
            &base_mint,
            &quote_mint,
            &payer,
            &token_base_program,
            &token_quote_program,
            amount_in,
            minimum_amount_out,
        );

        assert_eq!(instruction.program_id, DBC_PROGRAM_ID);
        let mut expected_data = hash(SWAP2_NAME).to_bytes()[..8].to_vec();
        expected_data.extend_from_slice(&amount_in.to_le_bytes());
        expected_data.extend_from_slice(&minimum_amount_out.to_le_bytes());
        expected_data.push(0); // SwapMode::ExactIn
        assert_eq!(instruction.data, expected_data);

        let expected_accounts = [
            pool_authority,
            config,
            pool,
            input,
            output,
            base_vault,
            quote_vault,
            base_mint,
            quote_mint,
            payer,
            token_base_program,
            token_quote_program,
            DBC_PROGRAM_ID, // no-referral sentinel
            event_authority(),
            DBC_PROGRAM_ID,
            instructions_sysvar,
        ];
        assert_eq!(instruction.accounts.len(), expected_accounts.len());
        for (index, (account, expected_key)) in instruction
            .accounts
            .iter()
            .zip(expected_accounts)
            .enumerate()
        {
            assert_eq!(account.pubkey, expected_key);
            assert_eq!(account.is_signer, index == 9);
            assert_eq!(
                account.is_writable,
                matches!(index, 2 | 3 | 4 | 5 | 6 | 9)
            );
        }
    }

    #[test]
    fn pool_address_sorts_mints_for_the_meteora_seed() {
        let config = Pubkey::new_unique();
        let base_mint = Pubkey::new_unique();
        let quote_mint = Pubkey::new_unique();
        let (max_mint, min_mint) = if base_mint.to_bytes() > quote_mint.to_bytes() {
            (&base_mint, &quote_mint)
        } else {
            (&quote_mint, &base_mint)
        };

        let expected = Pubkey::find_program_address(
            &[
                b"pool",
                config.as_ref(),
                max_mint.as_ref(),
                min_mint.as_ref(),
            ],
            &DBC_PROGRAM_ID,
        )
        .0;

        assert_eq!(pool_address(&config, &base_mint, &quote_mint), expected);
        assert_eq!(pool_address(&config, &quote_mint, &base_mint), expected);
    }
}