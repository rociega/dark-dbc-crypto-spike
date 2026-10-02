#![allow(deprecated)]

use solana_program::{
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    hash::hash,
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    system_program,
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token::state::{Account as SplTokenAccount, AccountState, Mint};

use launch_shield_program::process_instruction;

const DBC_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");
const VERIFIED_SBF_SHA256: [u8; 32] = [
    0xab, 0x0e, 0x74, 0xf0, 0xe0, 0x74, 0xf5, 0xc8, 0xc4, 0x7b, 0x98, 0x98, 0xe0, 0x78, 0x6a, 0x8f,
    0xe0, 0x91, 0xad, 0x10, 0x49, 0x73, 0x43, 0xf3, 0x85, 0xda, 0xd3, 0xce, 0x8b, 0xb0, 0x11, 0x15,
];

fn system_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: Vec::new(),
        owner: system_program::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn program_data_account(upgrade_authority: Pubkey) -> Account {
    let data_len = UpgradeableLoaderState::size_of_programdata_metadata();
    let state = UpgradeableLoaderState::ProgramData {
        slot: 1,
        upgrade_authority_address: Some(upgrade_authority),
    };
    let serialized = bincode::serialize(&state).unwrap();
    assert_eq!(serialized.len(), data_len);
    let mut data = vec![0; data_len];
    data.copy_from_slice(&serialized);
    Account {
        lamports: Rent::default().minimum_balance(data_len),
        data,
        owner: bpf_loader_upgradeable::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn upgradeable_program_data_account(upgrade_authority: Pubkey, elf: &[u8]) -> Account {
    let metadata_len = UpgradeableLoaderState::size_of_programdata_metadata();
    let state = UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: Some(upgrade_authority),
    };
    let mut data = bincode::serialize(&state).unwrap();
    assert_eq!(data.len(), metadata_len);
    data.extend_from_slice(elf);
    Account {
        lamports: Rent::default().minimum_balance(data.len()),
        data,
        owner: bpf_loader_upgradeable::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn upgradeable_program_account(program_data: Pubkey) -> Account {
    let data = bincode::serialize(&UpgradeableLoaderState::Program {
        programdata_address: program_data,
    })
    .unwrap();
    assert_eq!(data.len(), UpgradeableLoaderState::size_of_program());
    Account {
        lamports: Rent::default().minimum_balance(data.len()),
        data,
        owner: bpf_loader_upgradeable::id(),
        executable: true,
        rent_epoch: 0,
    }
}

fn mint_account(authority: Pubkey) -> Account {
    let mut data = vec![0; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::Some(authority),
            supply: 0,
            decimals: 6,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    Account {
        lamports: Rent::default().minimum_balance(data.len()),
        data,
        owner: spl_token::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn token_account(mint: Pubkey, owner: Pubkey) -> Account {
    let mut data = vec![0; SplTokenAccount::LEN];
    SplTokenAccount::pack(
        SplTokenAccount {
            mint,
            owner,
            amount: 0,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    Account {
        lamports: Rent::default().minimum_balance(data.len()),
        data,
        owner: spl_token::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn test_vkey_hash() -> [u8; 66] {
    format!("0x{}", "11".repeat(32))
        .as_bytes()
        .try_into()
        .unwrap()
}

fn initialize_config_ix(program_id: Pubkey, authority: Pubkey) -> Instruction {
    let (config, _) = Pubkey::find_program_address(&[b"global-config"], &program_id);
    let program_data = bpf_loader_upgradeable::get_program_data_address(&program_id);
    let mut data = vec![0];
    data.extend_from_slice(&test_vkey_hash());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(program_data, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

fn initialize_auction_ix(
    program_id: Pubkey,
    creator: Pubkey,
    auction_id: [u8; 32],
    quote_mint: Pubkey,
    quote_vault: Pubkey,
    dbc_config: Pubkey,
) -> Instruction {
    let (config, _) = Pubkey::find_program_address(&[b"global-config"], &program_id);
    let (auction, _) = Pubkey::find_program_address(&[b"auction", &auction_id], &program_id);
    let mut data = vec![1];
    data.extend_from_slice(&auction_id);
    for value in [4_u64, 5, 1_000, 1_000_000, 1, 1] {
        data.extend_from_slice(&value.to_le_bytes());
    }
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(creator, true),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new(auction, false),
            AccountMeta::new_readonly(quote_mint, false),
            AccountMeta::new_readonly(quote_vault, false),
            AccountMeta::new_readonly(dbc_config, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

fn program_test(
    program_id: Pubkey,
    authority: &Keypair,
    recorded_upgrade_authority: Pubkey,
    dbc_config: Pubkey,
    dbc_owner: Pubkey,
    quote_mint: Pubkey,
    quote_vault: Pubkey,
) -> ProgramTest {
    let mut test = ProgramTest::new(
        "launch_shield_program",
        program_id,
        processor!(|program_id, accounts, instruction_data| {
            process_instruction(program_id, accounts, instruction_data)
        }),
    );
    test.add_account(
        bpf_loader_upgradeable::get_program_data_address(&program_id),
        program_data_account(recorded_upgrade_authority),
    );
    test.add_account(authority.pubkey(), system_account(10_000_000_000));
    test.add_account(quote_mint, mint_account(authority.pubkey()));
    let (auction, _) = Pubkey::find_program_address(&[b"auction", &[7; 32]], &program_id);
    let (vault_authority, _) =
        Pubkey::find_program_address(&[b"vault", auction.as_ref()], &program_id);
    test.add_account(quote_vault, token_account(quote_mint, vault_authority));
    test.add_account(
        dbc_config,
        Account {
            lamports: Rent::default().minimum_balance(0),
            data: Vec::new(),
            owner: dbc_owner,
            executable: false,
            rent_epoch: 0,
        },
    );
    test
}

fn upgradeable_program_test(
    program_id: Pubkey,
    authority: &Keypair,
    recorded_upgrade_authority: Pubkey,
    dbc_config: Pubkey,
    dbc_owner: Pubkey,
    quote_mint: Pubkey,
    quote_vault: Pubkey,
) -> ProgramTest {
    let mut test = ProgramTest::default();
    let elf_dir = std::env::var("BPF_OUT_DIR")
        .expect("BPF_OUT_DIR must identify the verified SBF artifact");
    let elf_path = std::path::Path::new(&elf_dir).join("launch_shield_program.so");
    let elf = std::fs::read(&elf_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", elf_path.display()));
    assert_eq!(
        hash(&elf).to_bytes(),
        VERIFIED_SBF_SHA256,
        "BPF_OUT_DIR does not contain the SBF artifact recorded for Devnet"
    );
    let program_data = bpf_loader_upgradeable::get_program_data_address(&program_id);
    test.add_genesis_account(program_id, upgradeable_program_account(program_data));
    test.add_genesis_account(
        program_data,
        upgradeable_program_data_account(recorded_upgrade_authority, &elf),
    );
    test.add_account(authority.pubkey(), system_account(10_000_000_000));
    test.add_account(quote_mint, mint_account(authority.pubkey()));
    let (auction, _) = Pubkey::find_program_address(&[b"auction", &[7; 32]], &program_id);
    let (vault_authority, _) =
        Pubkey::find_program_address(&[b"vault", auction.as_ref()], &program_id);
    test.add_account(quote_vault, token_account(quote_mint, vault_authority));
    test.add_account(
        dbc_config,
        Account {
            lamports: Rent::default().minimum_balance(0),
            data: Vec::new(),
            owner: dbc_owner,
            executable: false,
            rent_epoch: 0,
        },
    );
    test
}

#[tokio::test]
async fn initializes_config_and_auction_in_the_solana_runtime() {
    let program_id = Pubkey::new_unique();
    let authority = Keypair::new();
    let quote_mint = Pubkey::new_unique();
    let quote_vault = Pubkey::new_unique();
    let dbc_config = Pubkey::new_unique();
    let test = program_test(
        program_id,
        &authority,
        authority.pubkey(),
        dbc_config,
        DBC_PROGRAM_ID,
        quote_mint,
        quote_vault,
    );
    let context = test.start_with_context().await;
    let auction_id = [7; 32];
    let instructions = [
        initialize_config_ix(program_id, authority.pubkey()),
        initialize_auction_ix(
            program_id,
            authority.pubkey(),
            auction_id,
            quote_mint,
            quote_vault,
            dbc_config,
        ),
    ];
    let mut transaction = Transaction::new_with_payer(&instructions, Some(&context.payer.pubkey()));
    transaction.sign(&[&context.payer, &authority], context.last_blockhash);
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    let (config, _) = Pubkey::find_program_address(&[b"global-config"], &program_id);
    let config_account = context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(config_account.owner, program_id);
    assert_eq!(&config_account.data[..8], b"SHCFG001");
    assert_eq!(&config_account.data[8..40], authority.pubkey().as_ref());
    assert_eq!(&config_account.data[40..], &test_vkey_hash());

    let (auction, _) = Pubkey::find_program_address(&[b"auction", &auction_id], &program_id);
    let auction_account = context
        .banks_client
        .get_account(auction)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auction_account.owner, program_id);
    assert_eq!(auction_account.data.len(), 363);
    assert_eq!(&auction_account.data[..8], b"SHWIN001");
}

#[tokio::test]
#[ignore = "requires BPF_OUT_DIR pointing to the verified deployed SBF artifact"]
async fn executes_verified_sbf_under_the_upgradeable_loader() {
    let program_id = Pubkey::new_unique();
    let authority = Keypair::new();
    let quote_mint = Pubkey::new_unique();
    let quote_vault = Pubkey::new_unique();
    let dbc_config = Pubkey::new_unique();
    let test = upgradeable_program_test(
        program_id,
        &authority,
        authority.pubkey(),
        dbc_config,
        DBC_PROGRAM_ID,
        quote_mint,
        quote_vault,
    );
    let context = test.start_with_context().await;
    let auction_id = [7; 32];
    let instructions = [
        initialize_config_ix(program_id, authority.pubkey()),
        initialize_auction_ix(
            program_id,
            authority.pubkey(),
            auction_id,
            quote_mint,
            quote_vault,
            dbc_config,
        ),
    ];
    let mut transaction = Transaction::new_with_payer(&instructions, Some(&context.payer.pubkey()));
    transaction.sign(&[&context.payer, &authority], context.last_blockhash);
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    let program_account = context
        .banks_client
        .get_account(program_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(program_account.owner, bpf_loader_upgradeable::id());
    assert!(program_account.executable);

    let (config, _) = Pubkey::find_program_address(&[b"global-config"], &program_id);
    let config_account = context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(config_account.owner, program_id);
    assert_eq!(&config_account.data[..8], b"SHCFG001");
    assert_eq!(&config_account.data[8..40], authority.pubkey().as_ref());
    assert_eq!(&config_account.data[40..], &test_vkey_hash());

    let (auction, _) = Pubkey::find_program_address(&[b"auction", &auction_id], &program_id);
    let auction_account = context
        .banks_client
        .get_account(auction)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auction_account.owner, program_id);
    assert_eq!(auction_account.data.len(), 363);
    assert_eq!(&auction_account.data[..8], b"SHWIN001");
}

#[tokio::test]
async fn failed_auction_creation_rolls_back_the_config_in_the_same_transaction() {
    let program_id = Pubkey::new_unique();
    let authority = Keypair::new();
    let quote_mint = Pubkey::new_unique();
    let quote_vault = Pubkey::new_unique();
    let dbc_config = Pubkey::new_unique();
    let test = program_test(
        program_id,
        &authority,
        authority.pubkey(),
        dbc_config,
        system_program::id(),
        quote_mint,
        quote_vault,
    );
    let context = test.start_with_context().await;
    let auction_id = [7; 32];
    let instructions = [
        initialize_config_ix(program_id, authority.pubkey()),
        initialize_auction_ix(
            program_id,
            authority.pubkey(),
            auction_id,
            quote_mint,
            quote_vault,
            dbc_config,
        ),
    ];
    let mut transaction = Transaction::new_with_payer(&instructions, Some(&context.payer.pubkey()));
    transaction.sign(&[&context.payer, &authority], context.last_blockhash);
    assert!(context
        .banks_client
        .process_transaction(transaction)
        .await
        .is_err());

    let (config, _) = Pubkey::find_program_address(&[b"global-config"], &program_id);
    let (auction, _) = Pubkey::find_program_address(&[b"auction", &auction_id], &program_id);
    assert!(context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .is_none());
    assert!(context
        .banks_client
        .get_account(auction)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn config_initialization_rejects_a_non_upgrade_authority() {
    let program_id = Pubkey::new_unique();
    let authority = Keypair::new();
    let quote_mint = Pubkey::new_unique();
    let quote_vault = Pubkey::new_unique();
    let dbc_config = Pubkey::new_unique();
    let test = program_test(
        program_id,
        &authority,
        Pubkey::new_unique(),
        dbc_config,
        DBC_PROGRAM_ID,
        quote_mint,
        quote_vault,
    );
    let context = test.start_with_context().await;
    let instruction = initialize_config_ix(program_id, authority.pubkey());
    let mut transaction =
        Transaction::new_with_payer(&[instruction], Some(&context.payer.pubkey()));
    transaction.sign(&[&context.payer, &authority], context.last_blockhash);
    assert!(context
        .banks_client
        .process_transaction(transaction)
        .await
        .is_err());

    let (config, _) = Pubkey::find_program_address(&[b"global-config"], &program_id);
    assert!(context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .is_none());
}
