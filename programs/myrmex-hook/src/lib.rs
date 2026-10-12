//! MYRMEX transfer hook: counts every Token-2022 transfer in a per-mint stats PDA.
//! The hook never blocks a legitimate transfer and never changes balances.
#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::{create_program_address, find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::{declare_id, pubkey};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

declare_id!("HookMyrmex1111111111111111111111111111111111");

#[cfg(not(feature = "no-entrypoint"))]
pinocchio::entrypoint!(process_instruction);
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();

/// First 8 bytes of sha256("spl-transfer-hook-interface:execute").
pub const EXECUTE_DISCRIMINATOR: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];
/// First 8 bytes of sha256("spl-transfer-hook-interface:initialize-extra-account-metas").
pub const INITIALIZE_DISCRIMINATOR: [u8; 8] = [43, 34, 13, 49, 167, 88, 235, 235];

pub const TOKEN_2022_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const SYSTEM_ID: Pubkey = [0u8; 32];

pub const STATS_SEED: &[u8] = b"colony";
pub const META_SEED: &[u8] = b"extra-account-metas";

/// Stats account layout: [tag u8 = 1][bump u8][pad 6][count u64 LE].
pub const STATS_LEN: usize = 16;
const STATS_TAG: u8 = 1;
const COUNT_OFFSET: usize = 8;

/// TLV: type(8) + length u32(4) + count u32(4) + one ExtraAccountMeta(35).
const META_LEN: usize = 8 + 4 + 4 + 35;

const ACCOUNT_TYPE_OFFSET: usize = 165;
const ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const TRANSFER_HOOK_ACCOUNT_EXT: u16 = 15;

const ERR_NOT_TRANSFERRING: u32 = 1;

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (disc, rest) = data.split_at(8);
    if disc == EXECUTE_DISCRIMINATOR {
        // rest = amount u64
        if rest.len() < 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        execute(program_id, accounts)
    } else if disc == INITIALIZE_DISCRIMINATOR {
        initialize(program_id, accounts)
    } else {
        Err(ProgramError::InvalidInstructionData)
    }
}

fn execute(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // [0] source, [1] mint, [2] destination, [3] owner, [4] extra metas, [5] stats
    let [source, mint, destination, _owner, _metas, stats, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    check_token_account(source, mint.key())?;
    check_token_account(destination, mint.key())?;
    if !is_transferring(source)? {
        return Err(ProgramError::Custom(ERR_NOT_TRANSFERRING));
    }

    if !stats.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if !stats.is_owned_by(program_id) {
        return Err(ProgramError::UninitializedAccount);
    }
    let mut d = stats.try_borrow_mut_data()?;
    if d.len() != STATS_LEN || d[0] != STATS_TAG {
        return Err(ProgramError::UninitializedAccount);
    }
    let bump = [d[1]];
    let expected = create_program_address(&[STATS_SEED, mint.key().as_ref(), &bump], program_id)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    if &expected != stats.key() {
        return Err(ProgramError::InvalidSeeds);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&d[COUNT_OFFSET..COUNT_OFFSET + 8]);
    let count = u64::from_le_bytes(buf).saturating_add(1);
    d[COUNT_OFFSET..COUNT_OFFSET + 8].copy_from_slice(&count.to_le_bytes());
    Ok(())
}

fn check_token_account(acc: &AccountInfo, mint: &Pubkey) -> ProgramResult {
    if !acc.is_owned_by(&TOKEN_2022_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let d = acc.try_borrow_data()?;
    if d.len() < 32 || &d[0..32] != mint.as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

/// Reads the TransferHookAccount.transferring flag of a Token-2022 account.
fn is_transferring(source: &AccountInfo) -> Result<bool, ProgramError> {
    let d = source.try_borrow_data()?;
    if d.len() <= ACCOUNT_TYPE_OFFSET || d[ACCOUNT_TYPE_OFFSET] != ACCOUNT_TYPE_ACCOUNT {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut off = ACCOUNT_TYPE_OFFSET + 1;
    while off + 4 <= d.len() {
        let ty = u16::from_le_bytes([d[off], d[off + 1]]);
        let len = u16::from_le_bytes([d[off + 2], d[off + 3]]) as usize;
        let start = off + 4;
        let end = start
            .checked_add(len)
            .filter(|e| *e <= d.len())
            .ok_or(ProgramError::InvalidAccountData)?;
        if ty == TRANSFER_HOOK_ACCOUNT_EXT {
            if len < 1 {
                return Err(ProgramError::InvalidAccountData);
            }
            return Ok(d[start] != 0);
        }
        off = end;
    }
    Err(ProgramError::InvalidAccountData)
}

fn initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // [0] extra metas PDA, [1] mint, [2] mint authority (signer, payer), [3] system, [4] stats
    let [metas, mint, authority, system, stats, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if system.key() != &SYSTEM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable() || !metas.is_writable() || !stats.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if !mint.is_owned_by(&TOKEN_2022_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    {
        // COption<Pubkey> mint_authority at offset 0.
        let m = mint.try_borrow_data()?;
        if m.len() < 36
            || u32::from_le_bytes([m[0], m[1], m[2], m[3]]) != 1
            || &m[4..36] != authority.key().as_ref()
        {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }

    let mint_key = mint.key();
    let (metas_key, metas_bump) = find_program_address(&[META_SEED, mint_key.as_ref()], program_id);
    if &metas_key != metas.key() {
        return Err(ProgramError::InvalidSeeds);
    }
    let (stats_key, stats_bump) = find_program_address(&[STATS_SEED, mint_key.as_ref()], program_id);
    if &stats_key != stats.key() {
        return Err(ProgramError::InvalidSeeds);
    }

    let b = [metas_bump];
    let seeds = [Seed::from(META_SEED), Seed::from(mint_key.as_ref()), Seed::from(&b)];
    create_pda(authority, metas, META_LEN, program_id, Signer::from(&seeds))?;

    let b = [stats_bump];
    let seeds = [Seed::from(STATS_SEED), Seed::from(mint_key.as_ref()), Seed::from(&b)];
    create_pda(authority, stats, STATS_LEN, program_id, Signer::from(&seeds))?;

    {
        let mut d = stats.try_borrow_mut_data()?;
        d.fill(0);
        d[0] = STATS_TAG;
        d[1] = stats_bump;
    }

    // ExtraAccountMetaList TLV for Execute: one PDA (seeds "colony" + mint at account index 1),
    // not a signer, writable.
    let mut d = metas.try_borrow_mut_data()?;
    d.fill(0);
    d[0..8].copy_from_slice(&EXECUTE_DISCRIMINATOR);
    d[8..12].copy_from_slice(&39u32.to_le_bytes());
    d[12..16].copy_from_slice(&1u32.to_le_bytes());
    d[16] = 1; // PDA derived from this program
    let mut cfg = [0u8; 32];
    cfg[0] = 1; // literal seed
    cfg[1] = STATS_SEED.len() as u8;
    cfg[2..2 + STATS_SEED.len()].copy_from_slice(STATS_SEED);
    let p = 2 + STATS_SEED.len();
    cfg[p] = 3; // account key seed
    cfg[p + 1] = 1; // index 1 = mint
    d[17..49].copy_from_slice(&cfg);
    d[49] = 0; // is_signer
    d[50] = 1; // is_writable
    Ok(())
}

/// Creates a program-owned PDA account, also when someone pre-funded the address.
fn create_pda(
    payer: &AccountInfo,
    account: &AccountInfo,
    space: usize,
    owner: &Pubkey,
    signer: Signer,
) -> ProgramResult {
    if !account.is_owned_by(&SYSTEM_ID) || account.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    let required = Rent::get()?.minimum_balance(space);
    let current = account.lamports();
    if current == 0 {
        CreateAccount {
            from: payer,
            to: account,
            lamports: required,
            space: space as u64,
            owner,
        }
        .invoke_signed(&[signer])
    } else {
        if current < required {
            Transfer {
                from: payer,
                to: account,
                lamports: required - current,
            }
            .invoke()?;
        }
        Allocate {
            account,
            space: space as u64,
        }
        .invoke_signed(&[signer.clone()])?;
        Assign { account, owner }.invoke_signed(&[signer])
    }
}
