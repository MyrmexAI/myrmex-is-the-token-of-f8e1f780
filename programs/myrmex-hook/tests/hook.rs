use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction, system_program,
    transaction::Transaction,
};
use spl_token_2022::{
    extension::{transfer_hook, ExtensionType},
    state::{Account as TokenAccount, Mint},
};

const DECIMALS: u8 = 6;

fn program_id() -> Pubkey {
    myrmex_hook::ID.into()
}

fn disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(name.as_bytes());
    h[..8].try_into().unwrap()
}

struct Env {
    svm: LiteSVM,
    payer: Keypair,
    mint_auth: Keypair,
    mint: Pubkey,
    metas: Pubkey,
    stats: Pubkey,
    alice: Keypair,
    alice_ta: Pubkey,
    bob_ta: Pubkey,
}

impl Env {
    fn send(&mut self, ixs: &[Instruction], extra: &[&Keypair]) -> Result<(), String> {
        self.svm.expire_blockhash();
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new_signed_with_payer(
            ixs,
            Some(&self.payer.pubkey()),
            &signers,
            self.svm.latest_blockhash(),
        );
        self.svm
            .send_transaction(tx)
            .map(|_| ())
            .map_err(|e| format!("{:?} {:?}", e.err, e.meta.logs))
    }

    fn init_ix(&self) -> Instruction {
        let mut data = disc("spl-transfer-hook-interface:initialize-extra-account-metas").to_vec();
        data.extend_from_slice(&0u32.to_le_bytes());
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(self.metas, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.mint_auth.pubkey(), true),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new(self.stats, false),
            ],
            data,
        }
    }

    fn init(&mut self) -> Result<(), String> {
        let ix = self.init_ix();
        let auth = self.mint_auth.insecure_clone();
        self.send(&[ix], &[&auth])
    }

    fn transfer_ix(&self, from: &Pubkey, to: &Pubkey, owner: &Pubkey, amount: u64) -> Instruction {
        let mut ix = spl_token_2022::instruction::transfer_checked(
            &spl_token_2022::id(),
            from,
            &self.mint,
            to,
            owner,
            &[],
            amount,
            DECIMALS,
        )
        .unwrap();
        ix.accounts.push(AccountMeta::new(self.stats, false));
        ix.accounts.push(AccountMeta::new_readonly(program_id(), false));
        ix.accounts.push(AccountMeta::new_readonly(self.metas, false));
        ix
    }

    fn transfer(&mut self, amount: u64) -> Result<(), String> {
        let ix = self.transfer_ix(
            &self.alice_ta,
            &self.bob_ta,
            &self.alice.pubkey(),
            amount,
        );
        let alice = self.alice.insecure_clone();
        self.send(&[ix], &[&alice])
    }

    fn count(&self) -> u64 {
        let d = self.svm.get_account(&self.stats).unwrap().data;
        assert_eq!(d.len(), 16);
        u64::from_le_bytes(d[8..16].try_into().unwrap())
    }

    fn balance(&self, ta: &Pubkey) -> u64 {
        let d = self.svm.get_account(ta).unwrap().data;
        u64::from_le_bytes(d[64..72].try_into().unwrap())
    }
}

fn setup() -> Env {
    let mut svm = LiteSVM::new();
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/myrmex_hook.so");
    svm.add_program_from_file(program_id(), so)
        .expect("run `cargo build-sbf` before `cargo test`");

    let payer = Keypair::new();
    let mint_auth = Keypair::new();
    let alice = Keypair::new();
    let bob = Keypair::new();
    let mint_kp = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&mint_auth.pubkey(), 10_000_000_000).unwrap();
    let mint = mint_kp.pubkey();

    let (metas, _) = Pubkey::find_program_address(&[b"extra-account-metas", mint.as_ref()], &program_id());
    let (stats, _) = Pubkey::find_program_address(&[b"colony", mint.as_ref()], &program_id());

    let mint_len = ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::TransferHook]).unwrap();
    let ta_len =
        ExtensionType::try_calculate_account_len::<TokenAccount>(&[ExtensionType::TransferHookAccount]).unwrap();
    let alice_ta_kp = Keypair::new();
    let bob_ta_kp = Keypair::new();

    let t22 = spl_token_2022::id();
    let ixs = vec![
        system_instruction::create_account(
            &payer.pubkey(),
            &mint,
            svm.minimum_balance_for_rent_exemption(mint_len),
            mint_len as u64,
            &t22,
        ),
        transfer_hook::instruction::initialize(
            &t22,
            &mint,
            Some(mint_auth.pubkey()),
            Some(program_id()),
        )
        .unwrap(),
        spl_token_2022::instruction::initialize_mint2(&t22, &mint, &mint_auth.pubkey(), None, DECIMALS).unwrap(),
        system_instruction::create_account(
            &payer.pubkey(),
            &alice_ta_kp.pubkey(),
            svm.minimum_balance_for_rent_exemption(ta_len),
            ta_len as u64,
            &t22,
        ),
        spl_token_2022::instruction::initialize_account3(&t22, &alice_ta_kp.pubkey(), &mint, &alice.pubkey())
            .unwrap(),
        system_instruction::create_account(
            &payer.pubkey(),
            &bob_ta_kp.pubkey(),
            svm.minimum_balance_for_rent_exemption(ta_len),
            ta_len as u64,
            &t22,
        ),
        spl_token_2022::instruction::initialize_account3(&t22, &bob_ta_kp.pubkey(), &mint, &bob.pubkey()).unwrap(),
        spl_token_2022::instruction::mint_to_checked(
            &t22,
            &mint,
            &alice_ta_kp.pubkey(),
            &mint_auth.pubkey(),
            &[],
            1_000_000,
            DECIMALS,
        )
        .unwrap(),
    ];
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer, &mint_kp, &alice_ta_kp, &bob_ta_kp, &mint_auth],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("setup failed");

    Env {
        svm,
        payer,
        mint_auth,
        mint,
        metas,
        stats,
        alice,
        alice_ta: alice_ta_kp.pubkey(),
        bob_ta: bob_ta_kp.pubkey(),
    }
}

#[test]
fn discriminators_match_interface() {
    assert_eq!(
        myrmex_hook::EXECUTE_DISCRIMINATOR,
        disc("spl-transfer-hook-interface:execute")
    );
    assert_eq!(
        myrmex_hook::INITIALIZE_DISCRIMINATOR,
        disc("spl-transfer-hook-interface:initialize-extra-account-metas")
    );
}

#[test]
fn init_creates_state_and_validation_list() {
    let mut env = setup();
    env.init().unwrap();
    assert_eq!(env.count(), 0);
    let m = env.svm.get_account(&env.metas).unwrap();
    assert_eq!(m.owner, program_id());
    // Matches what spl-tlv-account-resolution parses for one PDA meta.
    assert_eq!(&m.data[0..8], &disc("spl-transfer-hook-interface:execute"));
    assert_eq!(u32::from_le_bytes(m.data[8..12].try_into().unwrap()), 39);
    assert_eq!(u32::from_le_bytes(m.data[12..16].try_into().unwrap()), 1);
    assert_eq!(m.data[16], 1);
    assert_eq!(&m.data[17..27], &[1, 6, b'c', b'o', b'l', b'o', b'n', b'y', 3, 1]);
    assert_eq!(&m.data[49..51], &[0, 1]);
    assert_eq!(env.svm.get_account(&env.stats).unwrap().owner, program_id());
}

#[test]
fn one_transfer_counts_one() {
    let mut env = setup();
    env.init().unwrap();
    env.transfer(100).unwrap();
    assert_eq!(env.count(), 1);
    assert_eq!(env.balance(&env.alice_ta), 1_000_000 - 100);
    assert_eq!(env.balance(&env.bob_ta), 100);
}

#[test]
fn three_transfers_count_three() {
    let mut env = setup();
    env.init().unwrap();
    for _ in 0..3 {
        env.transfer(10).unwrap();
    }
    assert_eq!(env.count(), 3);
    assert_eq!(env.balance(&env.bob_ta), 30);
}

#[test]
fn direct_execute_outside_transfer_fails() {
    let mut env = setup();
    env.init().unwrap();
    let mut data = disc("spl-transfer-hook-interface:execute").to_vec();
    data.extend_from_slice(&1u64.to_le_bytes());
    let ix = Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new_readonly(env.alice_ta, false),
            AccountMeta::new_readonly(env.mint, false),
            AccountMeta::new_readonly(env.bob_ta, false),
            AccountMeta::new_readonly(env.alice.pubkey(), true),
            AccountMeta::new_readonly(env.metas, false),
            AccountMeta::new(env.stats, false),
        ],
        data,
    };
    let alice = env.alice.insecure_clone();
    let err = env.send(&[ix], &[&alice]).unwrap_err();
    assert!(err.contains("Custom(1)"), "unexpected error: {err}");
    assert_eq!(env.count(), 0);
}

#[test]
fn transfer_before_init_fails() {
    let mut env = setup();
    assert!(env.transfer(10).is_err());
    assert_eq!(env.balance(&env.bob_ta), 0);
}

#[test]
fn init_requires_mint_authority_and_cannot_repeat() {
    let mut env = setup();

    // Someone else signing as "authority" is rejected.
    let mut ix = env.init_ix();
    let intruder = Keypair::new();
    env.svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();
    ix.accounts[2] = AccountMeta::new(intruder.pubkey(), true);
    assert!(env.send(&[ix], &[&intruder]).is_err());

    env.init().unwrap();
    env.transfer(1).unwrap();
    assert!(env.init().is_err());
    assert_eq!(env.count(), 1);
}

#[test]
fn init_works_when_pdas_are_prefunded() {
    let mut env = setup();
    for k in [env.metas, env.stats] {
        env.svm.airdrop(&k, 1).unwrap();
    }
    env.init().unwrap();
    env.transfer(1).unwrap();
    assert_eq!(env.count(), 1);
}

#[test]
fn counter_saturates() {
    let mut env = setup();
    env.init().unwrap();
    let mut acc = env.svm.get_account(&env.stats).unwrap();
    acc.data[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    env.svm.set_account(env.stats, acc).unwrap();
    env.transfer(1).unwrap();
    assert_eq!(env.count(), u64::MAX);
}
