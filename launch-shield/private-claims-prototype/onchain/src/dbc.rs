use solana_program::{
    hash::hash,
    instruction::{AccountMeta, Instruction},
    pubkey::{pubkey, Pubkey},
};

pub const DBC_PROGRAM_ID: Pubkey = pubkey!("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");
const SWAP2_NAME: &[u8] = b"global:swap2";

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