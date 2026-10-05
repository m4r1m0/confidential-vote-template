//! CI-only end-to-end integration test for the ranked-voting template.
//!
//! Runs a full 3-voter ranked-choice scenario on the Esmeralda testnet. For primary testing,
//! see `templates/confidential_voting/tests/test.rs` (in-process, no testnet needed).

use anyhow::{Context, Result};
use futures::StreamExt;
use indexmap::IndexSet;
use ootle_rs::{
    Address, Network, ToAccountAddress, TransactionOutcome, TransactionRequest,
    builtin_templates::{
        UnsignedTransactionBuilder,
        account::IAccount,
        component::{IComponent, TransactionBuildable},
    },
    default_indexer_url,
    key_provider::PrivateKeyProvider,
    provider::{IndexerProvider, PendingTransaction, ProviderBuilder, WalletProvider},
    stealth::{Output, SignatureRequirements, StealthSignerRequirement, StealthTransfer},
    template_types::{
        Amount, ComponentAddress, ResourceAddress, TemplateAddress, UtxoAddress,
        constants::{TARI, TARI_TOKEN},
        crypto::PedersenCommitmentBytes,
    },
    transaction::TransactionSigner,
    wallet::OotleWallet,
};
use rcv_tally::TallyMethod;
use std::num::NonZeroU64;
use std::time::Duration;
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_ootle_transaction::{Epoch, args};
use tari_utilities::ByteArray;

// Publish the minified release build — minify it first with:
//   wasm-opt -Oz --enable-bulk-memory target/wasm32-unknown-unknown/release/confidential_voting.wasm \
//       -o target/wasm32-unknown-unknown/release/confidential_voting.min.wasm
const WASM_PATH: &str = "target/wasm32-unknown-unknown/release/confidential_voting.min.wasm";
const VOTER_COUNT: usize = 3;
const NUM_CANDIDATES: u32 = 3;
const NUM_WINNERS: u32 = 1;
const EXPIRES_AT_EPOCH: u64 = 100_000;
const CONVERT_AMOUNT: u64 = TARI;
/// Amount (micro-tTARI) transferred to each wallet from the funding (`deploy`) account on
/// the wallet daemon — replaces the public faucet, which is empty on the testnet. The
/// initiator needs enough to cover the publish fee (charged up front, unused refunded);
/// voters need the convert amount plus ballot fees.
const INITIATOR_FUNDING: u64 = 12_000_000;
const VOTER_FUNDING: u64 = 2_000_000;
/// Fee paid per ballot from the stealth TARI UTXO. Bucket-paid fees are taken in full with
/// no refund — the excess is burned to the fee pool (`pay_fee_from_bucket` has no refunds),
/// so this is a flat overpay above the actual fee. The uniform amount is intentional: every
/// ballot transaction reveals the same fee, keeping all ballot txns identical in shape.
const VOTE_FEE: u64 = 50_000;

/// Each voter's ranking: a permutation of 0..NUM_CANDIDATES (index 0 = first choice).
/// Scenario: 3 voters, 3 candidates.
///   Voter 0: [0, 2, 1]  → first choice 0
///   Voter 1: [1, 2, 0]  → first choice 1
///   Voter 2: [2, 0, 1]  → first choice 2
/// Round 1: 0=1, 1=1, 2=1. No majority. Eliminate 0 (lowest id tie-break).
/// Round 2: 1=1, 2=2 (voter 0's 2nd choice redistributes to 2). 2/3 = 67% > 50%.
/// Winner: candidate 2.
const VOTER_RANKINGS: [[u32; NUM_CANDIDATES as usize]; VOTER_COUNT] =
    [[0, 2, 1], [1, 2, 0], [2, 0, 1]];
const EXPECTED_WINNER: u32 = 2;

// ───────────────────────── FPTP yes/no scenario ─────────────────────────
// A first-past-the-post election with exactly two candidates is functionally a yes/no vote:
// candidate 0 = "yes", candidate 1 = "no". Each ballot is a single choice — the candidate
// with the most choices wins, with no majority required.

const FPTP_VOTER_COUNT: usize = 3;
const FPTP_NUM_CANDIDATES: u32 = 2;
const FPTP_NUM_WINNERS: u32 = 1;
/// Each voter's choice as a one-element ballot: [0] = "yes", [1] = "no".
/// Two "yes" votes vs one "no" → candidate 0 ("yes") wins 2-1.
const FPTP_VOTER_CHOICES: [[u32; 1]; FPTP_VOTER_COUNT] = [[0], [0], [1]];
const FPTP_EXPECTED_WINNER: u32 = 0;

type Provider = IndexerProvider<OotleWallet>;

async fn wait_for_commit(pending: &PendingTransaction, label: &str) -> Result<()> {
    print!("  {label}: pending {}... ", pending.tx_id());
    let outcome = pending.watch().await?;
    match outcome {
        TransactionOutcome::Commit => println!("COMMITTED"),
        other => {
            println!("FAILED: {other:?}");
            anyhow::bail!("{label} failed: {other:?}");
        }
    }
    Ok(())
}

/// Every transaction must carry a bounded validity window: the last epoch in which it may be
/// sequenced. Current epoch plus a margin for confirmation time.
async fn max_epoch(provider: &Provider) -> Result<Epoch> {
    Ok(Epoch(provider.get_epoch().await?.as_u64() + 10))
}

/// Funds a wallet by transferring tTARI from the `deploy` account on the wallet daemon.
/// The public testnet faucet is empty, so the canonical funding path is a plain account
/// transfer: the daemon submits `accounts.transfer` from the funding account to the
/// wallet's account public key, and the destination account is created on first receive.
///
/// Requires two environment variables:
///   OOTLE_FUNDING_RPC_URL   wallet-daemon JSON-RPC URL (default: the local tunnel)
///   OOTLE_FUNDING_TOKEN     an Admin bearer token for the wallet daemon
async fn fund_from_deploy(address: &Address, amount: u64, label: &str) -> Result<()> {
    let url = std::env::var("OOTLE_FUNDING_RPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5100/json_rpc".to_string());
    let token = std::env::var("OOTLE_FUNDING_TOKEN")
        .context("OOTLE_FUNDING_TOKEN must be set (an Admin wallet-daemon token)")?;
    let destination_public_key = hex::encode(address.account_public_key().as_bytes());

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "accounts.transfer",
        "params": {
            "account": { "Name": "deploy" },
            "amount": amount,
            "resource_address": TARI_TOKEN,
            "destination_public_key": destination_public_key,
            "max_fee": 50_000,
            "dry_run": false,
        },
    });
    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .bearer_auth(&token)
        .json(&request)
        .send()
        .await
        .with_context(|| format!("funding RPC call to {url}"))?;
    let body: serde_json::Value = response
        .json()
        .await
        .context("reading funding RPC response")?;
    if let Some(error) = body.get("error") {
        anyhow::bail!("funding RPC error: {error}");
    }
    // The transfer RPC blocks until finalization and returns the result; the destination
    // account is created on first receive, so the wallet sees the funds after this call.
    let result = body
        .get("result")
        .context("funding RPC returned no result")?;
    let status = result
        .pointer("/result/result")
        .and_then(|r| r.as_str())
        .unwrap_or("unknown");
    println!("\n[{label}] funded via deploy account transfer ({status})");
    Ok(())
}

/// Publish fee for the publish step. Unused fee is refunded, so overpaying costs nothing; the
/// required fee scales with WASM size (the minified ~309 KB build needs ~9.6M). If publishing
/// starts failing with `OnlyFeeCommit(InsufficientFeesPaid("Required fees X but Y paid"))`,
/// bump this to comfortably exceed X.
const PUBLISH_FEE: u64 = 10_000_000;

async fn publish_template(provider: &mut Provider) -> Result<TemplateAddress> {
    print!("\n[Publish] template... ");
    let wasm = std::fs::read(WASM_PATH).with_context(|| format!("read {WASM_PATH}"))?;
    let unsigned = IAccount::new(provider, max_epoch(provider).await?)
        .publish_template(wasm)
        .pay_fee(PUBLISH_FEE)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait_for_commit(&pending, "publish").await?;
    let receipt = pending.get_receipt().await?;
    let template_address = receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|s| s.substate_id.as_template())
        .context("no template addr")?
        .as_template_address();
    println!("  template: {template_address}");
    Ok(template_address)
}

async fn create_and_initiate_vote(
    provider: &mut Provider,
    template_address: TemplateAddress,
    voter_addresses: &[Address],
    num_candidates: u32,
    num_winners: u32,
    tally_method: TallyMethod,
) -> Result<(
    ComponentAddress,
    ResourceAddress,
    Vec<(PedersenCommitmentBytes, RistrettoPublicKey)>,
)> {
    print!("\n[Create + Initiate] vote... ");
    let voter_count = voter_addresses.len() as u64;

    // Build the mint statement: one stealth ballot UTXO (amount-1) per voter.
    //
    // The StealthTransfer builder requires a ResourceAddress to construct, but the resulting
    // StealthTransferStatement does NOT embed it — the resource address is only used for
    // resolving stealth inputs (which we don't have; this is a revealed-input mint). So we pass
    // a placeholder address here. The real resource address is bound when the engine executes
    // the stealth_transfer instruction inside the template's `new()` constructor, which
    // receives the allocated address via the ResourceAddressAllocation parameter.
    let placeholder_resource = ResourceAddress::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .expect("valid placeholder resource address");
    let mut mint_builder =
        StealthTransfer::new(placeholder_resource, provider).spend_revealed_input(voter_count);
    for address in voter_addresses {
        let mut ballot_output = Output::new(
            address.clone(),
            placeholder_resource,
            NonZeroU64::new(1).expect("non-zero"),
        );
        // The template requires every ballot output to promise at least one token; the engine's
        // range proof then pins the committed value to exactly 1 (given the total and output
        // count, see `new`). The promise is public and reveals only that the ballot is ≥1 — every
        // ballot is exactly 1 by design, so no additional information is disclosed.
        ballot_output.minimum_value_promise = 1;
        mint_builder = mint_builder.to_stealth_output(ballot_output);
    }
    let (mint_statement, _) = mint_builder.prepare().await?;
    let ballot_utxos: Vec<(PedersenCommitmentBytes, RistrettoPublicKey)> = mint_statement
        .stealth_outputs()
        .iter()
        .map(|utxo| {
            let commitment = utxo.commitment().clone();
            let nonce: RistrettoPublicKey = RistrettoPublicKey::from_canonical_bytes(
                utxo.output.sender_public_nonce.as_bytes(),
            )
            .expect("valid sender nonce");
            (commitment, nonce)
        })
        .collect();

    // The template asserts the same invariants at construction; check them here so a misconfigured
    // builder fails fast before submitting an unrecoverable node transaction.
    assert_eq!(
        mint_statement.stealth_outputs().len() as u64,
        voter_count,
        "mint statement must create one stealth output per voter",
    );
    assert!(
        mint_statement
            .stealth_outputs()
            .iter()
            .all(|utxo| utxo.output.minimum_value_promise >= 1),
        "each ballot output must promise a minimum value of 1",
    );

    // Create the component and start the vote in a single transaction.
    let unsigned = IComponent::new(provider, max_epoch(provider).await?)
        .then(|builder| builder.allocate_resource_address("ballot_res"))
        .call_function(
            template_address,
            "new",
            args![
                Workspace("ballot_res"),
                voter_count,
                num_candidates,
                num_winners,
                tally_method,
                EXPIRES_AT_EPOCH,
                mint_statement,
            ],
        )
        .pay_fee(50_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait_for_commit(&pending, "create + initiate").await?;
    let receipt = pending.get_receipt().await?;
    let component = receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|s| s.substate_id.as_component_address())
        .context("no component addr")?;
    // The template creates two resources: RVOTE-MINT (NonFungible, ballot records) and RVOTE
    // (Stealth, the ballots themselves). Fetch each resource created by the receipt and pick
    // the stealth one that is not TARI.
    let mut created_resources: Vec<ResourceAddress> = receipt
        .diff_summary
        .upped
        .iter()
        .filter_map(|s| s.substate_id.as_resource_address())
        .filter(|a| *a != TARI_TOKEN)
        .collect();
    created_resources.sort();
    created_resources.dedup();
    let mut ballot_resource = None;
    for address in created_resources {
        if provider
            .get_resource(address)
            .await?
            .resource_type()
            .is_stealth()
        {
            ballot_resource = Some(address);
            break;
        }
    }
    let ballot_resource = ballot_resource.context("no ballot resource addr")?;
    // The ballot outputs were created by this transaction, so its commit epoch is the exact
    // lower bound for any later scan of the resource: every ballot's row carries `epoch >=
    // initiate_epoch`, and the bound keeps the scan's history walk limited to the election.
    let _initiate_epoch = receipt.epoch;
    println!("  component: {component}\n  ballot resource: {ballot_resource}");
    Ok((component, ballot_resource, ballot_utxos))
}

async fn convert_to_stealth_tari(
    provider: &mut Provider,
    voter_address: &Address,
) -> Result<(PedersenCommitmentBytes, RistrettoPublicKey)> {
    let voter_account = voter_address.to_account_address();
    let tari_utxo_value = CONVERT_AMOUNT - VOTE_FEE;

    let (convert_transfer, _) = StealthTransfer::new(TARI_TOKEN, provider)
        .spend_revealed_input(CONVERT_AMOUNT)
        .to_stealth_output(Output::new(
            voter_address.clone(),
            TARI_TOKEN,
            NonZeroU64::new(tari_utxo_value).expect("non-zero utxo value"),
        ))
        .to_revealed_output(VOTE_FEE)
        .prepare()
        .await?;

    let tari_utxo = &convert_transfer.stealth_outputs()[0];
    let tari_commitment = *tari_utxo.commitment();
    let tari_nonce: RistrettoPublicKey =
        RistrettoPublicKey::from_canonical_bytes(tari_utxo.output.sender_public_nonce.as_bytes())
            .expect("valid tari nonce");

    let unsigned = IComponent::new(provider, max_epoch(provider).await?)
        .want_vault_for(voter_account, TARI_TOKEN, true)
        .then(|builder| {
            builder.with_fee_instructions_builder(|fee_builder| {
                fee_builder
                    .call_method(
                        voter_account,
                        "withdraw",
                        args![TARI_TOKEN, Amount::from(CONVERT_AMOUNT)],
                    )
                    .put_last_instruction_output_on_workspace("withdrawn")
                    .stealth_transfer_with_input_bucket(TARI_TOKEN, convert_transfer, "withdrawn")
                    .put_last_instruction_output_on_workspace("fee_output")
                    .pay_fee_from_bucket("fee_output")
            })
        })
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    wait_for_commit(&provider.send_transaction(tx).await?, "convert").await?;

    Ok((tari_commitment, tari_nonce))
}

/// Casts a ballot via a two-input stealth spend: the ballot-token UTXO is the seal input
/// (spent into `cast_ballot`) and a stealth TARI UTXO pays the fee. This is the canonical
/// pattern for the README's fee-from-stealth requirement — the fee MUST come from a stealth
/// TARI UTXO, never a revealed account, or the transaction links the voter's identity to
/// their public ranking.
#[allow(clippy::too_many_arguments)]
async fn cast_private_ballot(
    provider: &mut Provider,
    component: ComponentAddress,
    ballot_resource: ResourceAddress,
    voter_address: &Address,
    ballot_commitment: PedersenCommitmentBytes,
    ballot_nonce: RistrettoPublicKey,
    tari_commitment: PedersenCommitmentBytes,
    tari_nonce: RistrettoPublicKey,
    ranking: Vec<u32>,
) -> Result<()> {
    let tari_change = CONVERT_AMOUNT - VOTE_FEE - VOTE_FEE;

    let (ballot_spend, _) = StealthTransfer::new(ballot_resource, provider)
        .spend_stealth_input(voter_address.clone(), ballot_commitment)
        .to_revealed_output(1u64)
        .prepare()
        .await?;
    let (tari_spend, _) = StealthTransfer::new(TARI_TOKEN, provider)
        .spend_stealth_input(voter_address.clone(), tari_commitment)
        .to_revealed_output(VOTE_FEE)
        .to_stealth_output(Output::new(
            voter_address.clone(),
            TARI_TOKEN,
            NonZeroU64::new(tari_change).expect("non-zero change"),
        ))
        .prepare()
        .await?;

    let ballot_signer = StealthSignerRequirement::new(voter_address.clone(), ballot_nonce);
    let tari_signer = StealthSignerRequirement::new(voter_address.clone(), tari_nonce);
    let mut authorizers = IndexSet::new();
    authorizers.insert(tari_signer);
    // The ballot-token UTXO seals the transaction (its one-time key P is the seal key) and the
    // stealth TARI fee UTXO authorizes against it.
    let signature_requirements =
        SignatureRequirements::stealth_seal_with(ballot_signer, authorizers);

    let unsigned = IComponent::new(provider, max_epoch(provider).await?)
        .want_all_vaults(component)
        .then(|builder| {
            builder
                .stealth_transfer(ballot_resource, ballot_spend)
                .put_last_instruction_output_on_workspace("vote")
                .add_input(ballot_resource)
                .add_input(UtxoAddress::new(ballot_resource, ballot_commitment.into()))
                .add_input(TARI_TOKEN)
                .add_input(UtxoAddress::new(TARI_TOKEN, tari_commitment.into()))
                .with_fee_instructions_builder(|fee_builder| {
                    fee_builder
                        .stealth_transfer(TARI_TOKEN, tari_spend)
                        .put_last_instruction_output_on_workspace("fees")
                        .pay_fee_from_bucket("fees")
                })
        })
        .call_method(component, "cast_ballot", args![Workspace("vote"), ranking])
        .prepare()
        .await?;

    let authorizer = provider.wallet().stealth_authorizer(signature_requirements);
    // Preflight (kept intentionally): dry-run the exact unsigned transaction so a
    // fee/invalidity failure aborts here, before spending real fees on-chain.
    let dry_run = provider
        .sign_and_send_dry_run_with(&authorizer, unsigned.clone())
        .await?;
    dry_run.expect_success();

    // `build` asks the authorizer for the stealth authorization signatures its inputs require
    // (committing to the seal signer's one-time public key) and seals the transaction.
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(&authorizer)
        .await?;
    wait_for_commit(&provider.send_transaction(tx).await?, "cast_ballot").await
}

async fn end_vote_and_read_result(
    provider: &mut Provider,
    component: ComponentAddress,
) -> Result<Option<u32>> {
    print!("\n[Result] end_vote()... ");
    let unsigned = IComponent::new(provider, max_epoch(provider).await?)
        .call_method(component, "end_vote", args![])
        .pay_fee(5_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait_for_commit(&pending, "end_vote").await?;
    let receipt = pending.get_receipt().await?;
    let mut winner = None;
    for event in receipt.events.iter() {
        println!("  event: {} {{{}}}", event.topic(), event.payload());
        // The tally events (`Result`, `ResultFptp`, ...) carry the winner under `winner`.
        if let Some(w) = event
            .payload()
            .get("winner")
            .and_then(|v| v.decode::<String>().ok())
        {
            winner = w.parse::<u32>().ok();
        }
    }
    Ok(winner)
}

/// Runs one election end-to-end: creates fresh voter wallets, initiates the vote with the given
/// configuration, has each voter discover their ballot UTXO and cast privately, then ends the
/// vote and returns the winner from the tally event.
#[allow(clippy::too_many_arguments)]
async fn run_election(
    initiator_provider: &mut Provider,
    template_address: TemplateAddress,
    voter_count: usize,
    num_candidates: u32,
    num_winners: u32,
    tally_method: TallyMethod,
    ballots: &[Vec<u32>],
    label: &str,
) -> Result<Option<u32>> {
    let network = Network::Esmeralda;

    let voter_wallets: Vec<(OotleWallet, Address, RistrettoSecretKey)> = (0..voter_count)
        .map(|i| {
            let secret = PrivateKeyProvider::random(network);
            let address = secret.address().clone();
            let view_secret = secret.credentials().view_only_secret().clone();
            println!("  voter {i} address: {address}");
            (OotleWallet::from(secret), address, view_secret)
        })
        .collect();
    let voter_addresses: Vec<Address> = voter_wallets.iter().map(|(_, a, _)| a.clone()).collect();

    let (component, ballot_resource, ballot_utxos) = create_and_initiate_vote(
        initiator_provider,
        template_address,
        &voter_addresses,
        num_candidates,
        num_winners,
        tally_method,
    )
    .await?;

    for (i, (wallet, voter_address, _view_secret)) in voter_wallets.into_iter().enumerate() {
        println!("\n[Voter {i}] cast ballot ranking={:?}", ballots[i]);

        let mut voter_provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_with_transaction_timeout(
                default_indexer_url(network),
                Duration::from_secs(120),
            )
            .await?;

        // Each voter spends the ballot UTXO the initiator minted for them in the mint
        // statement (the test harness uses the direct commitments for determinism; the
        // reference UTXO-scan flow is documented in the README).
        let (ballot_commitment, ballot_nonce) = &ballot_utxos[i];
        println!("  ballot UTXO: {}", hex::encode(ballot_commitment));

        fund_from_deploy(&voter_address, VOTER_FUNDING, &format!("Voter {i}")).await?;
        let (tari_commitment, tari_nonce) =
            convert_to_stealth_tari(&mut voter_provider, &voter_address).await?;
        cast_private_ballot(
            &mut voter_provider,
            component,
            ballot_resource,
            &voter_address,
            ballot_commitment.clone(),
            ballot_nonce.clone(),
            tari_commitment,
            tari_nonce,
            ballots[i].clone(),
        )
        .await?;
    }

    println!("\n[{label}] finalizing...");
    end_vote_and_read_result(initiator_provider, component).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::Esmeralda;

    let init_secret = PrivateKeyProvider::random(network);
    let init_address = init_secret.address().clone();
    let init_wallet = OotleWallet::from(init_secret);
    println!("Initiator: {init_address}");

    let mut initiator_provider = ProviderBuilder::new()
        .wallet(init_wallet)
        .connect_with_transaction_timeout(default_indexer_url(network), Duration::from_secs(120))
        .await?;
    println!("Connected to indexer");

    fund_from_deploy(&init_address, INITIATOR_FUNDING, "Initiator").await?;
    let template_address = publish_template(&mut initiator_provider).await?;

    // Election 1: single-winner ranked-choice IRV (3 voters, 3 candidates, 1 winner).
    println!("\n=== Election 1: ranked-choice IRV ===");
    let irv_winner = run_election(
        &mut initiator_provider,
        template_address,
        VOTER_COUNT,
        NUM_CANDIDATES,
        NUM_WINNERS,
        TallyMethod::Irv,
        &VOTER_RANKINGS
            .iter()
            .map(|r| r.to_vec())
            .collect::<Vec<_>>(),
        "IRV",
    )
    .await?;
    assert_eq!(
        irv_winner,
        Some(EXPECTED_WINNER),
        "IRV election produced the wrong winner: {irv_winner:?}",
    );

    // Election 2: FPTP yes/no vote (3 voters, 2 candidates = "yes"/"no", 1 winner).
    println!("\n=== Election 2: FPTP yes/no ===");
    let fptp_winner = run_election(
        &mut initiator_provider,
        template_address,
        FPTP_VOTER_COUNT,
        FPTP_NUM_CANDIDATES,
        FPTP_NUM_WINNERS,
        TallyMethod::Fptp,
        &FPTP_VOTER_CHOICES
            .iter()
            .map(|r| r.to_vec())
            .collect::<Vec<_>>(),
        "FPTP yes/no",
    )
    .await?;
    assert_eq!(
        fptp_winner,
        Some(FPTP_EXPECTED_WINNER),
        "FPTP election produced the wrong winner: {fptp_winner:?}",
    );

    println!(
        "\nINTEGRATION COMPLETE: IRV validated (winner = candidate {EXPECTED_WINNER}) and \
         FPTP yes/no validated (winner = candidate {FPTP_EXPECTED_WINNER})."
    );
    Ok(())
}
