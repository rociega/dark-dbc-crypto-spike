use solana_program::{
    account_info::AccountInfo,
    bpf_loader_upgradeable::UpgradeableLoaderState,
    clock::Clock,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};
use spl_token::{
    instruction as token_instruction,
    state::{Account as TokenAccount, AccountState, Mint},
};

use crate::{
    commitment,
    dbc::{self, DBC_PROGRAM_ID},
    error::{ShieldError, ShieldResult},
    instruction::{self, ShieldInstruction},
    state::{
        Auction, Bid, GlobalConfig, AUCTION_COMMITS, AUCTION_LEN, AUCTION_REVEALS,
        AUCTION_CANCELLED, AUCTION_SETTLED, AUCTION_SETTLING, BID_CANCELLED, BID_CLAIMED,
        BID_COMMITTED, BID_FORFEITED, BID_LEN, BID_REVEALED, CONFIG_LEN,
    },
};

const MAX_BIDS: u8 = 8;
const SETTLEMENT_GRACE_SLOTS: u64 = 256;

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    instruction_data: &[u8],
) -> ShieldResult {
    match instruction::unpack(instruction_data)? {
        ShieldInstruction::InitializeConfig { vkey_hash } => {
            initialize_config(program_id, accounts, vkey_hash)
        }
        ShieldInstruction::InitializeAuction {
            auction_id,
            commit_slots,
            reveal_slots,
            max_bid_amount,
            bond_lamports,
            min_output_numerator,
            min_output_denominator,
        } => initialize_auction(
            program_id,
            accounts,
            auction_id,
            commit_slots,
            reveal_slots,
            max_bid_amount,
            bond_lamports,
            min_output_numerator,
            min_output_denominator,
        ),
        ShieldInstruction::CommitBid {
            commitment: bid_hash,
            proof,
            public_values,
        } => commit_bid(program_id, accounts, bid_hash, &proof, &public_values),
        ShieldInstruction::RevealBid { amount, salt } => {
            reveal_bid(program_id, accounts, amount, salt)
        }
        ShieldInstruction::ForfeitUnrevealed => forfeit_unrevealed(program_id, accounts),
        ShieldInstruction::PrepareSettlement => prepare_settlement(program_id, accounts),
        ShieldInstruction::FinalizeSettlement => finalize_settlement(program_id, accounts),
        ShieldInstruction::Claim => claim(program_id, accounts),
        ShieldInstruction::CancelUnsettled => cancel_unsettled(program_id, accounts),
        ShieldInstruction::RefundCancelledBid => refund_cancelled_bid(program_id, accounts),
    }
}

fn initialize_config(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    vkey_hash: [u8; 66],
) -> ShieldResult {
    let authority = account(accounts, 0)?;
    let config_account = account(accounts, 1)?;
    let program_data_account = account(accounts, 2)?;
    let system_program = account(accounts, 3)?;
    require_signer(authority)?;
    require_writable(config_account)?;
    require_key(system_program, &solana_program::system_program::id())?;
    verify_upgrade_authority(program_id, authority, program_data_account)?;
    commitment::parse_vkey_hash(&vkey_hash).map_err(|_| ShieldError::InvalidVkeyHash)?;

    let (expected_config, bump) =
        Pubkey::find_program_address(&[b"global-config"], program_id);
    require_key(config_account, &expected_config)?;
    if config_account.owner != &solana_program::system_program::id() {
        return Err(ShieldError::InvalidAccount.into());
    }

    let bump_seed = [bump];
    create_program_account(
        authority,
        config_account,
        system_program,
        program_id,
        CONFIG_LEN,
        &[b"global-config", &bump_seed],
    )?;

    GlobalConfig {
        authority: *authority.key,
        sp1_vkey_hash: vkey_hash,
    }
    .pack(&mut config_account.try_borrow_mut_data()?)?;
    Ok(())
}

#[allow(deprecated)]
fn verify_upgrade_authority(
    program_id: &Pubkey,
    authority: &AccountInfo<'_>,
    program_data: &AccountInfo<'_>,
) -> ShieldResult {
    let expected_program_data =
        solana_program::bpf_loader_upgradeable::get_program_data_address(program_id);
    require_key(program_data, &expected_program_data)?;
    require_owner(
        program_data,
        &solana_program::bpf_loader_upgradeable::id(),
    )?;
    let data = program_data.try_borrow_data()?;
    let metadata_len = UpgradeableLoaderState::size_of_programdata_metadata();
    if data.len() < metadata_len {
        return Err(ShieldError::InvalidAccount.into());
    }
    let loader_state: UpgradeableLoaderState = bincode::deserialize(&data[..metadata_len])
        .map_err(|_| ShieldError::InvalidAccount)?;
    match loader_state {
        UpgradeableLoaderState::ProgramData {
            upgrade_authority_address: Some(upgrade_authority),
            ..
        } if authority.key == &upgrade_authority => Ok(()),
        _ => Err(ShieldError::Unauthorized.into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn initialize_auction(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    auction_id: [u8; 32],
    commit_slots: u64,
    reveal_slots: u64,
    max_bid_amount: u64,
    bond_lamports: u64,
    min_output_numerator: u64,
    min_output_denominator: u64,
) -> ShieldResult {
    let creator = account(accounts, 0)?;
    let config_account = account(accounts, 1)?;
    let auction_account = account(accounts, 2)?;
    let quote_mint_account = account(accounts, 3)?;
    let quote_vault_account = account(accounts, 4)?;
    let dbc_config_account = account(accounts, 5)?;
    let system_program = account(accounts, 6)?;

    require_signer(creator)?;
    require_writable(creator)?;
    require_writable(auction_account)?;
    require_key(system_program, &solana_program::system_program::id())?;
    require_owned(config_account, program_id)?;
    require_owned(dbc_config_account, &DBC_PROGRAM_ID)?;
    let global_config = GlobalConfig::unpack(&config_account.try_borrow_data()?)?;
    global_config
        .vkey_hash_str()
        .map_err(|_| ShieldError::InvalidVkeyHash)?;

    if commit_slots == 0
        || reveal_slots == 0
        || max_bid_amount == 0
        || max_bid_amount > u64::MAX / u64::from(MAX_BIDS)
        || bond_lamports == 0
        || min_output_denominator == 0
        || min_output_numerator == 0
    {
        return Err(ShieldError::InvalidAmount.into());
    }

    let (expected_auction, bump) =
        Pubkey::find_program_address(&[b"auction", &auction_id], program_id);
    require_key(auction_account, &expected_auction)?;
    if auction_account.owner != &solana_program::system_program::id() {
        return Err(ShieldError::InvalidAccount.into());
    }
    verify_config_address(program_id, config_account)?;

    let (vault_authority, _) = dbc::vault_authority(program_id, auction_account.key);
    let quote_mint = unpack_mint(quote_mint_account)?;
    let quote_vault = unpack_token_account(quote_vault_account)?;
    if quote_mint_account.owner != &spl_token::id()
        || quote_vault_account.owner != &spl_token::id()
        || quote_vault.mint != *quote_mint_account.key
        || quote_vault.owner != vault_authority
        || quote_vault.state != AccountState::Initialized
    {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    let _ = quote_mint;
    let clock = Clock::get()?;
    let commit_end_slot = clock
        .slot
        .checked_add(commit_slots)
        .ok_or(ShieldError::ArithmeticOverflow)?;
    let reveal_end_slot = commit_end_slot
        .checked_add(reveal_slots)
        .ok_or(ShieldError::ArithmeticOverflow)?;
    let settlement_deadline_slot = reveal_end_slot
        .checked_add(SETTLEMENT_GRACE_SLOTS)
        .ok_or(ShieldError::ArithmeticOverflow)?;

    let bump_seed = [bump];
    create_program_account(
        creator,
        auction_account,
        system_program,
        program_id,
        AUCTION_LEN,
        &[b"auction", &auction_id, &bump_seed],
    )?;

    Auction {
        creator: *creator.key,
        auction_id,
        quote_mint: *quote_mint_account.key,
        quote_vault: *quote_vault_account.key,
        dbc_config: *dbc_config_account.key,
        start_slot: clock.slot,
        commit_end_slot,
        reveal_end_slot,
        settlement_deadline_slot,
        max_bid_amount,
        bond_lamports,
        min_output_numerator,
        min_output_denominator,
        bid_count: 0,
        revealed_count: 0,
        total_revealed_amount: 0,
        status: AUCTION_COMMITS,
        settlement_q: 0,
        settlement_y: 0,
        dbc_pool: Pubkey::default(),
        base_mint: Pubkey::default(),
        base_output_vault: Pubkey::default(),
        output_balance_before: 0,
    }
    .pack(&mut auction_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn commit_bid(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    bid_hash: [u8; 32],
    proof: &[u8; instruction::SP1_PROOF_LEN],
    supplied_public_values: &[u8; instruction::BID_PUBLIC_VALUES_LEN],
) -> ShieldResult {
    let auction_account = account(accounts, 0)?;
    let config_account = account(accounts, 1)?;
    let bid_account = account(accounts, 2)?;
    let bidder = account(accounts, 3)?;
    let bidder_quote_account = account(accounts, 4)?;
    let quote_vault_account = account(accounts, 5)?;
    let quote_mint_account = account(accounts, 6)?;
    let vault_authority = account(accounts, 7)?;
    let token_program = account(accounts, 8)?;
    let system_program = account(accounts, 9)?;

    require_signer(bidder)?;
    require_writable(bidder)?;
    require_writable(auction_account)?;
    require_writable(bid_account)?;
    require_key(token_program, &spl_token::id())?;
    require_key(system_program, &solana_program::system_program::id())?;
    require_owned(auction_account, program_id)?;
    require_owned(config_account, program_id)?;
    verify_config_address(program_id, config_account)?;

    let mut auction = Auction::unpack(&auction_account.try_borrow_data()?)?;
    verify_auction_address(program_id, auction_account, &auction)?;
    let current_slot = Clock::get()?.slot;
    if auction.status != AUCTION_COMMITS
        || current_slot < auction.start_slot
        || current_slot >= auction.commit_end_slot
    {
        return Err(ShieldError::WrongWindow.into());
    }
    if auction.bid_count >= MAX_BIDS {
        return Err(ShieldError::BidLimitReached.into());
    }
    if quote_mint_account.key != &auction.quote_mint
        || quote_vault_account.key != &auction.quote_vault
    {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    let (expected_vault_authority, _) = dbc::vault_authority(program_id, auction_account.key);
    require_key(vault_authority, &expected_vault_authority)?;
    verify_token_account(
        bidder_quote_account,
        &auction.quote_mint,
        bidder.key,
        &spl_token::id(),
    )?;
    verify_token_account(
        quote_vault_account,
        &auction.quote_mint,
        &expected_vault_authority,
        &spl_token::id(),
    )?;

    let (expected_bid, bid_bump) = Pubkey::find_program_address(
        &[b"bid", auction_account.key.as_ref(), bidder.key.as_ref()],
        program_id,
    );
    require_key(bid_account, &expected_bid)?;
    require_owner(bid_account, &solana_program::system_program::id())?;

    let config = GlobalConfig::unpack(&config_account.try_borrow_data()?)?;
    let public_values = commitment::public_values(
        program_id,
        &auction.auction_id,
        bidder.key,
        &bid_hash,
        &auction.quote_mint,
        &auction.quote_vault,
        auction.max_bid_amount,
    );
    if public_values != *supplied_public_values {
        return Err(ShieldError::InvalidProof.into());
    }
    let vkey_hash = config
        .vkey_hash_str()
        .map_err(|_| ShieldError::InvalidVkeyHash)?;
    sp1_solana::verify_proof(
        proof,
        supplied_public_values,
        vkey_hash,
        sp1_solana::GROTH16_VK_5_0_0_BYTES,
    )
    .map_err(|_| ShieldError::InvalidProof)?;

    transfer_checked(
        token_program,
        bidder_quote_account,
        quote_mint_account,
        quote_vault_account,
        bidder,
        auction.max_bid_amount,
        unpack_mint(quote_mint_account)?.decimals,
        None,
    )?;
    invoke(
        &system_instruction::transfer(bidder.key, auction_account.key, auction.bond_lamports),
        &[bidder.clone(), auction_account.clone(), system_program.clone()],
    )?;

    let bump_seed = [bid_bump];
    create_program_account(
        bidder,
        bid_account,
        system_program,
        program_id,
        BID_LEN,
        &[
            b"bid",
            auction_account.key.as_ref(),
            bidder.key.as_ref(),
            &bump_seed,
        ],
    )?;
    Bid {
        auction: *auction_account.key,
        bidder: *bidder.key,
        commitment: bid_hash,
        slot: auction.bid_count,
        max_deposit: auction.max_bid_amount,
        amount: 0,
        status: BID_COMMITTED,
    }
    .pack(&mut bid_account.try_borrow_mut_data()?)?;
    auction.bid_count = auction
        .bid_count
        .checked_add(1)
        .ok_or(ShieldError::ArithmeticOverflow)?;
    auction.pack(&mut auction_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn reveal_bid(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    amount: u64,
    salt: [u8; 32],
) -> ShieldResult {
    let auction_account = account(accounts, 0)?;
    let bid_account = account(accounts, 1)?;
    let bidder = account(accounts, 2)?;
    let quote_vault_account = account(accounts, 3)?;
    let bidder_quote_account = account(accounts, 4)?;
    let quote_mint_account = account(accounts, 5)?;
    let vault_authority = account(accounts, 6)?;
    let token_program = account(accounts, 7)?;

    require_signer(bidder)?;
    require_writable(auction_account)?;
    require_writable(bid_account)?;
    require_writable(bidder)?;
    require_key(token_program, &spl_token::id())?;
    require_owned(auction_account, program_id)?;
    require_owned(bid_account, program_id)?;
    let mut auction = Auction::unpack(&auction_account.try_borrow_data()?)?;
    verify_auction_address(program_id, auction_account, &auction)?;
    let mut bid = Bid::unpack(&bid_account.try_borrow_data()?)?;
    verify_bid_address(program_id, auction_account, bidder, bid_account, &bid)?;
    if auction.status == AUCTION_SETTLING
        || auction.status == AUCTION_SETTLED
        || auction.status == AUCTION_CANCELLED
    {
        return Err(ShieldError::InvalidState.into());
    }
    let slot = Clock::get()?.slot;
    if slot < auction.commit_end_slot || slot >= auction.reveal_end_slot {
        return Err(ShieldError::WrongWindow.into());
    }
    if bid.status != BID_COMMITTED
        || amount == 0
        || amount > auction.max_bid_amount
        || bid.max_deposit != auction.max_bid_amount
        || bid.commitment
            != commitment::bid_commitment(
                program_id,
                &auction.auction_id,
                bidder.key,
                amount,
                &salt,
            )
    {
        return Err(ShieldError::InvalidCommitment.into());
    }
    if quote_mint_account.key != &auction.quote_mint
        || quote_vault_account.key != &auction.quote_vault
    {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    let (expected_vault_authority, bump) = dbc::vault_authority(program_id, auction_account.key);
    require_key(vault_authority, &expected_vault_authority)?;
    verify_token_account(
        quote_vault_account,
        &auction.quote_mint,
        &expected_vault_authority,
        &spl_token::id(),
    )?;
    verify_token_account(
        bidder_quote_account,
        &auction.quote_mint,
        bidder.key,
        &spl_token::id(),
    )?;

    let refund = auction
        .max_bid_amount
        .checked_sub(amount)
        .ok_or(ShieldError::ArithmeticOverflow)?;
    if refund > 0 {
        let bump_seed = [bump];
        transfer_checked(
            token_program,
            quote_vault_account,
            quote_mint_account,
            bidder_quote_account,
            vault_authority,
            refund,
            unpack_mint(quote_mint_account)?.decimals,
            Some(&[
                b"vault",
                auction_account.key.as_ref(),
                &bump_seed,
            ]),
        )?;
    }

    release_bond(
        auction_account,
        bidder,
        auction.bond_lamports,
        Rent::get()?.minimum_balance(AUCTION_LEN),
    )?;
    auction.total_revealed_amount = auction
        .total_revealed_amount
        .checked_add(amount)
        .ok_or(ShieldError::ArithmeticOverflow)?;
    auction.revealed_count = auction
        .revealed_count
        .checked_add(1)
        .ok_or(ShieldError::ArithmeticOverflow)?;
    auction.status = AUCTION_REVEALS;
    bid.amount = amount;
    bid.status = BID_REVEALED;
    bid.pack(&mut bid_account.try_borrow_mut_data()?)?;
    auction.pack(&mut auction_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn forfeit_unrevealed(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ShieldResult {
    let auction_account = account(accounts, 0)?;
    let bid_account = account(accounts, 1)?;
    let creator = account(accounts, 2)?;
    let creator_quote_account = account(accounts, 3)?;
    let quote_vault_account = account(accounts, 4)?;
    let quote_mint_account = account(accounts, 5)?;
    let vault_authority = account(accounts, 6)?;
    let token_program = account(accounts, 7)?;

    require_writable(auction_account)?;
    require_writable(bid_account)?;
    require_writable(creator)?;
    require_key(token_program, &spl_token::id())?;
    require_owned(auction_account, program_id)?;
    require_owned(bid_account, program_id)?;
    let auction = Auction::unpack(&auction_account.try_borrow_data()?)?;
    verify_auction_address(program_id, auction_account, &auction)?;
    if creator.key != &auction.creator || Clock::get()?.slot < auction.reveal_end_slot {
        return Err(ShieldError::WrongWindow.into());
    }
    let mut bid = Bid::unpack(&bid_account.try_borrow_data()?)?;
    if bid.auction != *auction_account.key
        || bid.status != BID_COMMITTED
        || bid.max_deposit != auction.max_bid_amount
    {
        return Err(ShieldError::InvalidState.into());
    }
    let (expected_bid, _) = Pubkey::find_program_address(
        &[
            b"bid",
            auction_account.key.as_ref(),
            bid.bidder.as_ref(),
        ],
        program_id,
    );
    require_key(bid_account, &expected_bid)?;
    if quote_mint_account.key != &auction.quote_mint
        || quote_vault_account.key != &auction.quote_vault
    {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    let (expected_vault_authority, bump) = dbc::vault_authority(program_id, auction_account.key);
    require_key(vault_authority, &expected_vault_authority)?;
    verify_token_account(
        creator_quote_account,
        &auction.quote_mint,
        creator.key,
        &spl_token::id(),
    )?;
    verify_token_account(
        quote_vault_account,
        &auction.quote_mint,
        &expected_vault_authority,
        &spl_token::id(),
    )?;
    let bump_seed = [bump];
    transfer_checked(
        token_program,
        quote_vault_account,
        quote_mint_account,
        creator_quote_account,
        vault_authority,
        bid.max_deposit,
        unpack_mint(quote_mint_account)?.decimals,
        Some(&[b"vault", auction_account.key.as_ref(), &bump_seed]),
    )?;
    release_bond(
        auction_account,
        creator,
        auction.bond_lamports,
        Rent::get()?.minimum_balance(AUCTION_LEN),
    )?;
    bid.status = BID_FORFEITED;
    bid.pack(&mut bid_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn prepare_settlement(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ShieldResult {
    let auction_account = account(accounts, 0)?;
    let quote_vault_account = account(accounts, 1)?;
    let vault_authority = account(accounts, 2)?;
    let quote_mint_account = account(accounts, 3)?;
    let creator = account(accounts, 4)?;
    let creator_input_account = account(accounts, 5)?;
    let base_mint_account = account(accounts, 6)?;
    let base_output_vault = account(accounts, 7)?;
    let dbc_config_account = account(accounts, 8)?;
    let dbc_base_vault = account(accounts, 9)?;
    let dbc_quote_vault = account(accounts, 10)?;
    let token_program = account(accounts, 11)?;
    let instructions_sysvar = account(accounts, 12)?;

    require_signer(creator)?;
    require_writable(auction_account)?;
    require_writable(quote_vault_account)?;
    require_writable(creator_input_account)?;
    require_writable(base_output_vault)?;
    require_key(token_program, &spl_token::id())?;
    require_owned(auction_account, program_id)?;
    let mut auction = Auction::unpack(&auction_account.try_borrow_data()?)?;
    verify_auction_address(program_id, auction_account, &auction)?;
    let current_slot = Clock::get()?.slot;
    if creator.key != &auction.creator
        || current_slot < auction.reveal_end_slot
        || current_slot >= auction.settlement_deadline_slot
        || auction.total_revealed_amount == 0
        || auction.status != AUCTION_REVEALS
    {
        return Err(ShieldError::InvalidState.into());
    }
    if quote_vault_account.key != &auction.quote_vault
        || quote_mint_account.key != &auction.quote_mint
        || dbc_config_account.key != &auction.dbc_config
        || dbc_config_account.owner != &DBC_PROGRAM_ID
        || dbc_base_vault.owner != &spl_token::id()
        || dbc_quote_vault.owner != &spl_token::id()
        || base_mint_account.owner != &spl_token::id()
    {
        return Err(ShieldError::InvalidPool.into());
    }
    let (expected_vault_authority, vault_bump) =
        dbc::vault_authority(program_id, auction_account.key);
    require_key(vault_authority, &expected_vault_authority)?;
    if creator_input_account.key
        != &dbc::associated_token_address(creator.key, &auction.quote_mint)
        || base_output_vault.key
            != &dbc::associated_token_address(&expected_vault_authority, base_mint_account.key)
    {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    verify_token_account(
        quote_vault_account,
        &auction.quote_mint,
        &expected_vault_authority,
        &spl_token::id(),
    )?;
    verify_token_account(
        creator_input_account,
        &auction.quote_mint,
        creator.key,
        &spl_token::id(),
    )?;
    let output_state = verify_token_account(
        base_output_vault,
        base_mint_account.key,
        &expected_vault_authority,
        &spl_token::id(),
    )?;
    if output_state.amount != 0 {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    let _base_mint = unpack_mint(base_mint_account)?;
    let quote_mint = unpack_mint(quote_mint_account)?;
    let quote_vault_state = unpack_token_account(quote_vault_account)?;
    let required_min_output = minimum_output_for(
        auction.total_revealed_amount,
        auction.min_output_numerator,
        auction.min_output_denominator,
    )?;
    if required_min_output == 0 {
        return Err(ShieldError::InvalidAmount.into());
    }
    if quote_vault_state.amount < auction.total_revealed_amount {
        return Err(ShieldError::InvalidTokenAccount.into());
    }

    let swap = dbc::verify_settlement_layout(
        instructions_sysvar,
        program_id,
        auction_account.key,
        creator.key,
        &auction.dbc_config,
        &auction.quote_mint,
        base_mint_account.key,
        auction.total_revealed_amount,
        required_min_output,
        creator_input_account.key,
        base_output_vault.key,
    )?;
    let expected_pool = dbc::pool_address(
        &auction.dbc_config,
        base_mint_account.key,
        &auction.quote_mint,
    );
    if swap.pool != expected_pool
        || swap.base_vault != *dbc_base_vault.key
        || swap.quote_vault != *dbc_quote_vault.key
        || swap.base_mint != *base_mint_account.key
        || swap.quote_mint != *quote_mint_account.key
        || swap.token_base_program != spl_token::id()
        || swap.token_quote_program != spl_token::id()
    {
        return Err(ShieldError::InvalidDbcInstruction.into());
    }

    transfer_checked(
        token_program,
        quote_vault_account,
        quote_mint_account,
        creator_input_account,
        vault_authority,
        auction.total_revealed_amount,
        quote_mint.decimals,
        Some(&[
            b"vault",
            auction_account.key.as_ref(),
            &[vault_bump],
        ]),
    )?;

    auction.status = AUCTION_SETTLING;
    auction.settlement_q = auction.total_revealed_amount;
    auction.settlement_y = 0;
    auction.dbc_pool = expected_pool;
    auction.base_mint = *base_mint_account.key;
    auction.base_output_vault = *base_output_vault.key;
    auction.output_balance_before = output_state.amount;
    auction.pack(&mut auction_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn finalize_settlement(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ShieldResult {
    let auction_account = account(accounts, 0)?;
    let creator = account(accounts, 1)?;
    let dbc_pool_account = account(accounts, 2)?;
    let base_mint_account = account(accounts, 3)?;
    let base_output_vault = account(accounts, 4)?;
    let instructions_sysvar = account(accounts, 5)?;
    require_signer(creator)?;
    require_writable(auction_account)?;
    require_owned(auction_account, program_id)?;
    let mut auction = Auction::unpack(&auction_account.try_borrow_data()?)?;
    verify_auction_address(program_id, auction_account, &auction)?;
    if auction.status != AUCTION_SETTLING
        || creator.key != &auction.creator
        || dbc_pool_account.key != &auction.dbc_pool
        || dbc_pool_account.owner != &DBC_PROGRAM_ID
        || base_mint_account.key != &auction.base_mint
        || base_output_vault.key != &auction.base_output_vault
    {
        return Err(ShieldError::InvalidState.into());
    }
    dbc::validate_finalize_predecessor(
        instructions_sysvar,
        program_id,
        auction_account.key,
        &auction.dbc_pool,
        auction.settlement_q,
        minimum_output(&auction)?,
        &dbc::associated_token_address(&auction.creator, &auction.quote_mint),
        base_output_vault.key,
        creator.key,
    )?;
    let output_state = verify_token_account(
        base_output_vault,
        &auction.base_mint,
        &dbc::vault_authority(program_id, auction_account.key).0,
        &spl_token::id(),
    )?;
    let output_amount = output_state
        .amount
        .checked_sub(auction.output_balance_before)
        .ok_or(ShieldError::ArithmeticOverflow)?;
    if output_amount < minimum_output(&auction)? {
        return Err(ShieldError::SlippageGuardFailed.into());
    }
    auction.settlement_y = output_amount;
    auction.status = AUCTION_SETTLED;
    auction.pack(&mut auction_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn claim(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ShieldResult {
    let auction_account = account(accounts, 0)?;
    let bid_account = account(accounts, 1)?;
    let bidder = account(accounts, 2)?;
    let base_output_vault = account(accounts, 3)?;
    let destination = account(accounts, 4)?;
    let base_mint_account = account(accounts, 5)?;
    let vault_authority = account(accounts, 6)?;
    let token_program = account(accounts, 7)?;

    require_signer(bidder)?;
    require_writable(auction_account)?;
    require_writable(bid_account)?;
    require_writable(base_output_vault)?;
    require_writable(destination)?;
    require_key(token_program, &spl_token::id())?;
    require_owned(auction_account, program_id)?;
    require_owned(bid_account, program_id)?;
    let auction = Auction::unpack(&auction_account.try_borrow_data()?)?;
    verify_auction_address(program_id, auction_account, &auction)?;
    let mut bid = Bid::unpack(&bid_account.try_borrow_data()?)?;
    verify_bid_address(program_id, auction_account, bidder, bid_account, &bid)?;
    let allocation = claim_allocation(&auction, &bid)?;
    if base_mint_account.key != &auction.base_mint
        || base_output_vault.key != &auction.base_output_vault
    {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    let (expected_vault_authority, bump) =
        dbc::vault_authority(program_id, auction_account.key);
    require_key(vault_authority, &expected_vault_authority)?;
    verify_token_account(
        base_output_vault,
        &auction.base_mint,
        &expected_vault_authority,
        &spl_token::id(),
    )?;
    let destination_state = unpack_token_account(destination)?;
    validate_claim_destination(
        destination.owner,
        &destination_state.mint,
        &destination_state.owner,
        destination_state.state,
        bidder.key,
        &auction.base_mint,
    )?;

    if allocation > 0 {
        transfer_checked(
            token_program,
            base_output_vault,
            base_mint_account,
            destination,
            vault_authority,
            allocation,
            unpack_mint(base_mint_account)?.decimals,
            Some(&[
                b"vault",
                auction_account.key.as_ref(),
                &[bump],
            ]),
        )?;
    }
    bid.status = BID_CLAIMED;
    bid.pack(&mut bid_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn cancel_unsettled(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ShieldResult {
    let auction_account = account(accounts, 0)?;
    require_writable(auction_account)?;
    require_owned(auction_account, program_id)?;
    let mut auction = Auction::unpack(&auction_account.try_borrow_data()?)?;
    verify_auction_address(program_id, auction_account, &auction)?;
    let next_status = cancellation_status(
        auction.status,
        Clock::get()?.slot,
        auction.settlement_deadline_slot,
    )?;
    if auction.status != next_status {
        auction.status = next_status;
        auction.pack(&mut auction_account.try_borrow_mut_data()?)?;
    }
    Ok(())
}

fn refund_cancelled_bid(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ShieldResult {
    let auction_account = account(accounts, 0)?;
    let bid_account = account(accounts, 1)?;
    let bidder = account(accounts, 2)?;
    let bidder_quote_account = account(accounts, 3)?;
    let quote_vault_account = account(accounts, 4)?;
    let quote_mint_account = account(accounts, 5)?;
    let vault_authority = account(accounts, 6)?;
    let token_program = account(accounts, 7)?;

    require_writable(auction_account)?;
    require_writable(bid_account)?;
    require_writable(bidder_quote_account)?;
    require_writable(quote_vault_account)?;
    require_key(token_program, &spl_token::id())?;
    require_owned(auction_account, program_id)?;
    require_owned(bid_account, program_id)?;
    let auction = Auction::unpack(&auction_account.try_borrow_data()?)?;
    verify_auction_address(program_id, auction_account, &auction)?;
    if auction.status != AUCTION_CANCELLED
        || quote_mint_account.key != &auction.quote_mint
        || quote_vault_account.key != &auction.quote_vault
    {
        return Err(ShieldError::InvalidState.into());
    }
    let mut bid = Bid::unpack(&bid_account.try_borrow_data()?)?;
    let refund_amount = cancelled_refund_amount(&auction, &bid)?;
    verify_bid_address(program_id, auction_account, bidder, bid_account, &bid)?;
    let (expected_vault_authority, bump) = dbc::vault_authority(program_id, auction_account.key);
    require_key(vault_authority, &expected_vault_authority)?;
    verify_token_account(
        quote_vault_account,
        &auction.quote_mint,
        &expected_vault_authority,
        &spl_token::id(),
    )?;
    verify_token_account(
        bidder_quote_account,
        &auction.quote_mint,
        bidder.key,
        &spl_token::id(),
    )?;
    let bump_seed = [bump];
    transfer_checked(
        token_program,
        quote_vault_account,
        quote_mint_account,
        bidder_quote_account,
        vault_authority,
        refund_amount,
        unpack_mint(quote_mint_account)?.decimals,
        Some(&[b"vault", auction_account.key.as_ref(), &bump_seed]),
    )?;
    bid.status = BID_CANCELLED;
    bid.pack(&mut bid_account.try_borrow_mut_data()?)?;
    Ok(())
}

fn minimum_output(auction: &Auction) -> ShieldResult<u64> {
    minimum_output_for(
        auction.settlement_q,
        auction.min_output_numerator,
        auction.min_output_denominator,
    )
}

fn pro_rata_allocation(amount: u64, output_total: u64, quote_total: u64) -> ShieldResult<u64> {
    if quote_total == 0 || amount > quote_total {
        return Err(ShieldError::InvalidState.into());
    }
    let product = u128::from(amount)
        .checked_mul(u128::from(output_total))
        .ok_or(ShieldError::ArithmeticOverflow)?;
    let allocation = product / u128::from(quote_total);
    u64::try_from(allocation).map_err(|_| ShieldError::ArithmeticOverflow.into())
}

fn cancellation_status(
    current_status: u8,
    current_slot: u64,
    deadline_slot: u64,
) -> ShieldResult<u8> {
    if current_slot < deadline_slot
        || current_status == AUCTION_SETTLING
        || current_status == AUCTION_SETTLED
    {
        return Err(ShieldError::WrongWindow.into());
    }
    Ok(AUCTION_CANCELLED)
}

fn claim_allocation(auction: &Auction, bid: &Bid) -> ShieldResult<u64> {
    if auction.status != AUCTION_SETTLED || bid.status != BID_REVEALED {
        return Err(ShieldError::InvalidState.into());
    }
    if auction.settlement_q == 0 || auction.settlement_y == 0 {
        return Err(ShieldError::InvalidState.into());
    }
    pro_rata_allocation(bid.amount, auction.settlement_y, auction.settlement_q)
}

fn validate_claim_destination(
    account_program: &Pubkey,
    account_mint: &Pubkey,
    account_authority: &Pubkey,
    account_state: AccountState,
    bidder: &Pubkey,
    base_mint: &Pubkey,
) -> ShieldResult {
    if account_program != &spl_token::id()
        || account_mint != base_mint
        || account_authority != bidder
        || account_state != AccountState::Initialized
    {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    Ok(())
}

fn cancelled_refund_amount(auction: &Auction, bid: &Bid) -> ShieldResult<u64> {
    if auction.status != AUCTION_CANCELLED || bid.status != BID_REVEALED || bid.amount == 0 {
        return Err(ShieldError::InvalidState.into());
    }
    Ok(bid.amount)
}

fn minimum_output_for(amount: u64, numerator: u64, denominator: u64) -> ShieldResult<u64> {
    let product = u128::from(amount)
        .checked_mul(u128::from(numerator))
        .ok_or(ShieldError::ArithmeticOverflow)?;
    let value = product
        .checked_div(u128::from(denominator))
        .ok_or(ShieldError::InvalidAmount)?;
    u64::try_from(value).map_err(|_| ShieldError::ArithmeticOverflow.into())
}

fn transfer_checked<'info>(
    token_program: &AccountInfo<'info>,
    source: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    amount: u64,
    decimals: u8,
    signer_seeds: Option<&[&[u8]]>,
) -> ShieldResult {
    if amount == 0 {
        return Ok(());
    }
    let ix = token_instruction::transfer_checked(
        token_program.key,
        source.key,
        mint.key,
        destination.key,
        authority.key,
        &[],
        amount,
        decimals,
    )?;
    let account_infos = [
        source.clone(),
        mint.clone(),
        destination.clone(),
        authority.clone(),
        token_program.clone(),
    ];
    if let Some(seeds) = signer_seeds {
        invoke_signed(&ix, &account_infos, &[seeds])?;
    } else {
        invoke(&ix, &account_infos)?;
    }
    Ok(())
}

fn create_program_account<'info>(
    payer: &AccountInfo<'info>,
    target: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    owner: &Pubkey,
    space: usize,
    seeds: &[&[u8]],
) -> ShieldResult {
    require_writable(payer)?;
    require_writable(target)?;
    require_key(system_program, &solana_program::system_program::id())?;
    require_owner(target, &solana_program::system_program::id())?;
    let rent = Rent::get()?.minimum_balance(space);
    let plan = program_account_creation_plan(target.lamports(), target.data_len(), rent)?;
    match plan {
        ProgramAccountCreationPlan::Create => {
            let space = u64::try_from(space).map_err(|_| ShieldError::ArithmeticOverflow)?;
            let ix = system_instruction::create_account(payer.key, target.key, rent, space, owner);
            invoke_signed(
                &ix,
                &[payer.clone(), target.clone(), system_program.clone()],
                &[seeds],
            )?;
        }
        ProgramAccountCreationPlan::AllocateAssign { rent_top_up } => {
            // Anyone can transfer lamports to a PDA. A regular create_account
            // then fails because the address is no longer empty, so initialize
            // the pre-funded system account in place instead.
            if rent_top_up > 0 {
                let fund_ix =
                    system_instruction::transfer(payer.key, target.key, rent_top_up);
                invoke(
                    &fund_ix,
                    &[payer.clone(), target.clone(), system_program.clone()],
                )?;
            }

            let space = u64::try_from(space).map_err(|_| ShieldError::ArithmeticOverflow)?;
            let allocate_ix = system_instruction::allocate(target.key, space);
            invoke_signed(
                &allocate_ix,
                &[target.clone(), system_program.clone()],
                &[seeds],
            )?;

            let assign_ix = system_instruction::assign(target.key, owner);
            invoke_signed(
                &assign_ix,
                &[target.clone(), system_program.clone()],
                &[seeds],
            )?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProgramAccountCreationPlan {
    Create,
    AllocateAssign { rent_top_up: u64 },
}

fn program_account_creation_plan(
    existing_lamports: u64,
    data_len: usize,
    rent_floor: u64,
) -> ShieldResult<ProgramAccountCreationPlan> {
    if data_len != 0 {
        return Err(ShieldError::InvalidAccount.into());
    }
    if existing_lamports == 0 {
        Ok(ProgramAccountCreationPlan::Create)
    } else {
        Ok(ProgramAccountCreationPlan::AllocateAssign {
            rent_top_up: rent_floor.saturating_sub(existing_lamports),
        })
    }
}

fn release_bond(
    auction: &AccountInfo<'_>,
    recipient: &AccountInfo<'_>,
    amount: u64,
    rent_floor: u64,
) -> ShieldResult {
    require_writable(auction)?;
    require_writable(recipient)?;
    let source_balance = auction.lamports();
    let recipient_balance = recipient.lamports();
    if source_balance < rent_floor.saturating_add(amount) {
        return Err(ShieldError::InvalidState.into());
    }
    let new_recipient_balance = recipient_balance
        .checked_add(amount)
        .ok_or(ShieldError::ArithmeticOverflow)?;
    **auction.try_borrow_mut_lamports()? = source_balance - amount;
    **recipient.try_borrow_mut_lamports()? = new_recipient_balance;
    Ok(())
}

fn verify_auction_address(
    program_id: &Pubkey,
    auction_account: &AccountInfo<'_>,
    auction: &Auction,
) -> ShieldResult {
    let (expected, _) =
        Pubkey::find_program_address(&[b"auction", &auction.auction_id], program_id);
    require_key(auction_account, &expected)
}

fn verify_bid_address(
    program_id: &Pubkey,
    auction_account: &AccountInfo<'_>,
    bidder: &AccountInfo<'_>,
    bid_account: &AccountInfo<'_>,
    bid: &Bid,
) -> ShieldResult {
    let (expected, _) = Pubkey::find_program_address(
        &[b"bid", auction_account.key.as_ref(), bidder.key.as_ref()],
        program_id,
    );
    if bid.auction != *auction_account.key || bid.bidder != *bidder.key {
        return Err(ShieldError::InvalidAccount.into());
    }
    require_key(bid_account, &expected)
}

fn verify_token_account(
    account: &AccountInfo<'_>,
    mint: &Pubkey,
    owner: &Pubkey,
    token_program: &Pubkey,
) -> Result<TokenAccount, ProgramError> {
    require_owner(account, token_program)?;
    let token = unpack_token_account(account)?;
    if token.mint != *mint || token.owner != *owner || token.state != AccountState::Initialized {
        return Err(ShieldError::InvalidTokenAccount.into());
    }
    Ok(token)
}

fn unpack_token_account(account: &AccountInfo<'_>) -> Result<TokenAccount, ProgramError> {
    TokenAccount::unpack(&account.try_borrow_data()?)
}

fn unpack_mint(account: &AccountInfo<'_>) -> Result<Mint, ProgramError> {
    require_owner(account, &spl_token::id())?;
    Mint::unpack(&account.try_borrow_data()?)
}

fn account<'a, 'info>(
    accounts: &'a [AccountInfo<'info>],
    index: usize,
) -> Result<&'a AccountInfo<'info>, ProgramError> {
    accounts.get(index).ok_or(ProgramError::NotEnoughAccountKeys)
}

fn require_signer(account: &AccountInfo<'_>) -> ShieldResult {
    if !account.is_signer {
        return Err(ShieldError::Unauthorized.into());
    }
    Ok(())
}

fn require_writable(account: &AccountInfo<'_>) -> ShieldResult {
    if !account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

fn require_owned(account: &AccountInfo<'_>, owner: &Pubkey) -> ShieldResult {
    require_owner(account, owner)
}

fn require_key(account: &AccountInfo<'_>, expected: &Pubkey) -> ShieldResult {
    if account.key != expected {
        return Err(ShieldError::InvalidAccount.into());
    }
    Ok(())
}

fn require_owner(account: &AccountInfo<'_>, expected: &Pubkey) -> ShieldResult {
    if account.owner != expected {
        return Err(ShieldError::InvalidAccount.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_auction(status: u8) -> Auction {
        Auction {
            creator: Pubkey::new_unique(),
            auction_id: [0; 32],
            quote_mint: Pubkey::new_unique(),
            quote_vault: Pubkey::new_unique(),
            dbc_config: Pubkey::new_unique(),
            start_slot: 0,
            commit_end_slot: 0,
            reveal_end_slot: 0,
            settlement_deadline_slot: 10,
            max_bid_amount: 100,
            bond_lamports: 0,
            min_output_numerator: 0,
            min_output_denominator: 1,
            bid_count: 1,
            revealed_count: 1,
            total_revealed_amount: 40,
            status,
            settlement_q: 100,
            settlement_y: 250,
            dbc_pool: Pubkey::new_unique(),
            base_mint: Pubkey::new_unique(),
            base_output_vault: Pubkey::new_unique(),
            output_balance_before: 0,
        }
    }

    fn test_bid(status: u8, amount: u64) -> Bid {
        Bid {
            auction: Pubkey::new_unique(),
            bidder: Pubkey::new_unique(),
            commitment: [0; 32],
            slot: 0,
            max_deposit: 100,
            amount,
            status,
        }
    }

    #[test]
    fn config_bootstrap_is_bound_to_the_program_upgrade_authority() {
        #[allow(deprecated)]
        let loader_id = solana_program::bpf_loader_upgradeable::id();
        let program_id = Pubkey::new_unique();
        let authority_key = Pubkey::new_unique();
        #[allow(deprecated)]
        let program_data_key =
            solana_program::bpf_loader_upgradeable::get_program_data_address(&program_id);
        let mut program_data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
            slot: 1,
            upgrade_authority_address: Some(authority_key),
        })
        .unwrap();
        let mut program_data_lamports = 1;
        let system_program_id = solana_program::system_program::id();
        let program_data_info = AccountInfo::new(
            &program_data_key,
            false,
            false,
            &mut program_data_lamports,
            &mut program_data,
            &loader_id,
            false,
            0,
        );
        let mut authority_lamports = 1;
        let mut authority_data = [];
        let authority_info = AccountInfo::new(
            &authority_key,
            true,
            false,
            &mut authority_lamports,
            &mut authority_data,
            &system_program_id,
            false,
            0,
        );
        verify_upgrade_authority(&program_id, &authority_info, &program_data_info).unwrap();

        let wrong_authority_key = Pubkey::new_unique();
        let mut wrong_authority_lamports = 1;
        let mut wrong_authority_data = [];
        let wrong_authority_info = AccountInfo::new(
            &wrong_authority_key,
            true,
            false,
            &mut wrong_authority_lamports,
            &mut wrong_authority_data,
            &system_program_id,
            false,
            0,
        );
        assert_eq!(
            verify_upgrade_authority(
                &program_id,
                &wrong_authority_info,
                &program_data_info
            ),
            Err(ShieldError::Unauthorized.into())
        );
    }

    #[test]
    fn minimum_output_uses_floor_rounding_and_rejects_zero_denominators() {
        assert_eq!(minimum_output_for(101, 2, 3).unwrap(), 67);
        assert_eq!(
            minimum_output_for(101, 2, 0),
            Err(ShieldError::InvalidAmount.into())
        );
    }

    #[test]
    fn minimum_output_rejects_values_that_do_not_fit_in_u64() {
        assert_eq!(
            minimum_output_for(u64::MAX, u64::MAX, 1),
            Err(ShieldError::ArithmeticOverflow.into())
        );
    }

    #[test]
    fn pro_rata_allocations_floor_round_without_exceeding_total_output() {
        let allocations = [10, 20, 70].map(|amount| {
            pro_rata_allocation(amount, 17, 100).unwrap()
        });
        let total_allocated = allocations.iter().sum::<u64>();
        assert_eq!(allocations, [1, 3, 11]);
        assert_eq!(total_allocated, 15);
        assert!(total_allocated <= 17);
        assert!(17 - total_allocated <= allocations.len() as u64 - 1);
    }

    #[test]
    fn pro_rata_allocation_rejects_inconsistent_state_and_handles_max_values() {
        assert_eq!(
            pro_rata_allocation(1, 17, 0),
            Err(ShieldError::InvalidState.into())
        );
        assert_eq!(
            pro_rata_allocation(101, 17, 100),
            Err(ShieldError::InvalidState.into())
        );
        assert_eq!(
            pro_rata_allocation(u64::MAX, u64::MAX, u64::MAX).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn cancellation_transition_obeys_deadline_and_settlement_guards() {
        assert_eq!(
            cancellation_status(AUCTION_REVEALS, 9, 10),
            Err(ShieldError::WrongWindow.into())
        );
        assert_eq!(
            cancellation_status(AUCTION_COMMITS, 10, 10).unwrap(),
            AUCTION_CANCELLED
        );
        assert_eq!(
            cancellation_status(AUCTION_REVEALS, 10, 10).unwrap(),
            AUCTION_CANCELLED
        );
        assert_eq!(
            cancellation_status(AUCTION_CANCELLED, 11, 10).unwrap(),
            AUCTION_CANCELLED
        );
        assert_eq!(
            cancellation_status(AUCTION_SETTLING, 11, 10),
            Err(ShieldError::WrongWindow.into())
        );
        assert_eq!(
            cancellation_status(AUCTION_SETTLED, 11, 10),
            Err(ShieldError::WrongWindow.into())
        );
    }

    #[test]
    fn claims_require_settled_auction_and_revealed_bid() {
        let settled = test_auction(AUCTION_SETTLED);
        let revealed = test_bid(BID_REVEALED, 40);
        assert_eq!(claim_allocation(&settled, &revealed).unwrap(), 100);

        assert_eq!(
            claim_allocation(&test_auction(AUCTION_REVEALS), &revealed),
            Err(ShieldError::InvalidState.into())
        );
        assert_eq!(
            claim_allocation(&settled, &test_bid(BID_CLAIMED, 40)),
            Err(ShieldError::InvalidState.into())
        );
        let mut zero_quote_total = settled;
        zero_quote_total.settlement_q = 0;
        assert_eq!(
            claim_allocation(&zero_quote_total, &revealed),
            Err(ShieldError::InvalidState.into())
        );
        let mut zero_output = settled;
        zero_output.settlement_y = 0;
        assert_eq!(
            claim_allocation(&zero_output, &revealed),
            Err(ShieldError::InvalidState.into())
        );
    }

    #[test]
    fn claim_destination_must_be_initialized_classic_token_account_for_bidder() {
        let token_program = spl_token::id();
        let bidder = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        validate_claim_destination(
            &token_program,
            &mint,
            &bidder,
            AccountState::Initialized,
            &bidder,
            &mint,
        )
        .unwrap();

        assert_eq!(
            validate_claim_destination(
                &token_program,
                &mint,
                &Pubkey::new_unique(),
                AccountState::Initialized,
                &bidder,
                &mint,
            ),
            Err(ShieldError::InvalidTokenAccount.into())
        );
        assert_eq!(
            validate_claim_destination(
                &Pubkey::new_unique(),
                &mint,
                &bidder,
                AccountState::Initialized,
                &bidder,
                &mint,
            ),
            Err(ShieldError::InvalidTokenAccount.into())
        );
        assert_eq!(
            validate_claim_destination(
                &token_program,
                &Pubkey::new_unique(),
                &bidder,
                AccountState::Initialized,
                &bidder,
                &mint,
            ),
            Err(ShieldError::InvalidTokenAccount.into())
        );
        assert_eq!(
            validate_claim_destination(
                &token_program,
                &mint,
                &bidder,
                AccountState::Frozen,
                &bidder,
                &mint,
            ),
            Err(ShieldError::InvalidTokenAccount.into())
        );
    }

    #[test]
    fn cancelled_refunds_require_cancelled_auction_and_positive_revealed_bid() {
        let cancelled = test_auction(AUCTION_CANCELLED);
        let revealed = test_bid(BID_REVEALED, 40);
        assert_eq!(cancelled_refund_amount(&cancelled, &revealed).unwrap(), 40);
        assert_eq!(
            cancelled_refund_amount(&test_auction(AUCTION_SETTLED), &revealed),
            Err(ShieldError::InvalidState.into())
        );
        assert_eq!(
            cancelled_refund_amount(&cancelled, &test_bid(BID_COMMITTED, 40)),
            Err(ShieldError::InvalidState.into())
        );
        assert_eq!(
            cancelled_refund_amount(&cancelled, &test_bid(BID_REVEALED, 0)),
            Err(ShieldError::InvalidState.into())
        );
    }

    #[test]
    fn program_account_creation_handles_prefunded_pdas_without_overfunding() {
        assert_eq!(
            program_account_creation_plan(0, 0, 1_000).unwrap(),
            ProgramAccountCreationPlan::Create
        );
        assert_eq!(
            program_account_creation_plan(1, 0, 1_000).unwrap(),
            ProgramAccountCreationPlan::AllocateAssign { rent_top_up: 999 }
        );
        assert_eq!(
            program_account_creation_plan(1_500, 0, 1_000).unwrap(),
            ProgramAccountCreationPlan::AllocateAssign { rent_top_up: 0 }
        );
        assert_eq!(
            program_account_creation_plan(500, 1, 1_000),
            Err(ShieldError::InvalidAccount.into())
        );
    }
}

fn verify_config_address(program_id: &Pubkey, config: &AccountInfo<'_>) -> ShieldResult {
    let (expected, _) = Pubkey::find_program_address(&[b"global-config"], program_id);
    require_key(config, &expected)
}