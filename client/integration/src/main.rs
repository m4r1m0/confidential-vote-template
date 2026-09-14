//! CI-only end-to-end integration test for the ranked-voting template.
//!
//! Runs a full 3-voter ranked-choice scenario on the Esmeralda testnet. For primary testing,
//! see `templates/ranked_voting/tests/test.rs` (in-process, no testnet needed).

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use indexmap::IndexSet;
use ootle_byte_type::FromByteType;
use ootle_rs::{
    Address, Network, ToAccountAddress, TransactionOutcome, TransactionRequest,
    builtin_templates::{
        UnsignedTransactionBuilder,
        account::IAccount,
        component::{IComponent, TransactionBuildable},
        faucet::IFaucet,
    },
    crypto::{StealthCryptoApi, encrypted_data},
    default_indexer_url,
    key_provider::PrivateKeyProvider,
    provider::{
        IndexerProvider, PendingTransaction, ProviderBuilder, ShardCursor, StealthUtxoFrame,
        StealthUtxoWatchRequest, WalletProvider,
    },
    stealth::{Output, SignatureRequirements, StealthSignerRequirement, StealthTransfer},
    template_types::{
        Amount, ComponentAddress, ResourceAddress, TemplateAddress, UtxoAddress,
        constants::{TARI, TARI_TOKEN},
        crypto::{PedersenCommitmentBytes, RistrettoPublicKeyBytes, UtxoTag},
    },
    transaction::TransactionSigner,
    wallet::OotleWallet,
};
use rcv_tally::TallyMethod;
use std::num::NonZeroU64;
use std::time::Duration;
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_ootle_transaction::{Epoch, args};

// Publish the minified release build — minify it first with:
//   wasm-opt -Oz --enable-bulk-memory target/wasm32-unknown-unknown/release/ranked_voting.wasm \
//       -o target/wasm32-unknown-unknown/release/ranked_voting.min.wasm
const WASM_PATH: &str = "target/wasm32-unknown-unknown/release/ranked_voting.min.wasm";
const VOTER_COUNT: usize = 3;
const NUM_CANDIDATES: u32 = 3;
const NUM_WINNERS: u32 = 1;
const EXPIRES_AT_EPOCH: u64 = 100_000;
const CONVERT_AMOUNT: u64 = TARI;
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
// candidate 0 = "yes", candidate 1 = "no". The tally counts first preferences only — the
// candidate with the most votes wins, with no majority required.

const FPTP_VOTER_COUNT: usize = 3;
const FPTP_NUM_CANDIDATES: u32 = 2;
const FPTP_NUM_WINNERS: u32 = 1;
/// Each voter's choice as a full ranking of the two candidates: [0, 1] = "yes", [1, 0] = "no".
/// Two "yes" votes vs one "no" → candidate 0 ("yes") wins 2-1.
const FPTP_VOTER_CHOICES: [[u32; FPTP_NUM_CANDIDATES as usize]; FPTP_VOTER_COUNT] =
    [[0, 1], [0, 1], [1, 0]];
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

async fn faucet(provider: &mut Provider, label: &str) -> Result<()> {
    print!("\n[{label}] Faucet... ");
    let unsigned = IFaucet::new(provider, max_epoch(provider).await?)
        .take_faucet_funds()
        .pay_fee(5_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    wait_for_commit(&provider.send_transaction(tx).await?, "faucet").await
}

/// Publish fee for the publish step. Unused fee is refunded, so overpaying costs nothing; the
/// required fee scales with WASM size (the minified ~309 KB build needs ~9.6M). If publishing
/// starts failing with `OnlyFeeCommit(InsufficientFeesPaid("Required fees X but Y paid"))`,
/// bump this to comfortably exceed X.
const PUBLISH_FEE: u64 = 20_000_000;

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
) -> Result<(ComponentAddress, ResourceAddress, Epoch)> {
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
    // (Stealth, the ballots themselves). The mint statement commits to the stealth resource, so
    // pick it out of the `resource.create` events rather than guessing from the diff order.
    let ballot_resource = receipt
        .events
        .iter()
        .find(|event| {
            event.topic() == "std.resource.create"
                && event.get_payload("resource_type") == Some("Stealth")
        })
        .and_then(|event| event.substate_id())
        .and_then(|s| s.as_resource_address())
        .context("no ballot resource addr")?;
    // The ballot outputs were created by this transaction, so its commit epoch is the exact
    // lower bound for any later scan of the resource: every ballot's row carries `epoch >=
    // initiate_epoch`, and the bound keeps the scan's history walk limited to the election.
    let initiate_epoch = receipt.epoch;
    println!("  component: {component}\n  ballot resource: {ballot_resource}");
    Ok((component, ballot_resource, initiate_epoch))
}

/// Discover a voter's own ballot UTXO by scanning the ballot resource's unspent stealth
/// outputs, instead of receiving the (commitment, nonce) from the initiator.
///
/// The indexer enumerates a resource's unspent UTXOs publicly as `(tag, sender public nonce)`
/// fetch keys; resolving them yields each output's commitment and DH-encrypted data. Only the
/// output addressed to this voter decrypts with the voter's view-only key (the encrypted
/// data's MAC validates), so a voter finds exactly their own ballot and learns nothing about
/// anyone else's. The commitment and sender public nonce are both public output fields — no
/// secret material is involved.
///
/// `from_epoch` bounds the scan to the resource's history since the vote's initiation epoch —
/// the ballot outputs were created then, so the full output set is covered without walking the
/// resource's pre-election history.
async fn find_my_ballot_utxo(
    provider: &Provider,
    voter_address: &Address,
    view_secret: &RistrettoSecretKey,
    ballot_resource: ResourceAddress,
    from_epoch: Epoch,
) -> Result<(PedersenCommitmentBytes, RistrettoPublicKey)> {
    // Drain the resource's UTXO update stream pass by pass, advancing the per-shard resume
    // cursor from each `EndOfShard` watermark. A single pass covers only a subset of shards, so
    // keep polling until every shard has been drained.
    let num_preshards = provider.get_num_preshards().await?;
    let mut cursor = ShardCursor::genesis(num_preshards);
    let mut observed = std::collections::HashSet::new();
    let total_shards = num_preshards.all_shards_iter().count();
    let mut fetch_keys: Vec<(UtxoTag, RistrettoPublicKeyBytes)> = Vec::new();
    while observed.len() < total_shards {
        let request = StealthUtxoWatchRequest {
            resource_address: ballot_resource,
            from_epoch,
            shard_state_versions: cursor.to_pairs(),
            unspent_only: true,
            per_shard_limit: 1000,
        };
        let mut stream = Box::pin(provider.watch_stealth_utxos(request).into_stream());
        let mut pass_progress = false;
        while let Some(frame) = stream.next().await {
            match frame.context("failed to watch ballot resource UTXOs")? {
                StealthUtxoFrame::Unspent { tag, public_nonce } => {
                    fetch_keys.push((tag, public_nonce))
                }
                StealthUtxoFrame::EndOfShard {
                    shard,
                    max_state_version,
                } => {
                    observed.insert(shard);
                    cursor.observe(shard, max_state_version);
                    pass_progress = true;
                }
                // `unspent_only` suppresses Spent/Burnt frames; StartOfShard carries no data.
                StealthUtxoFrame::StartOfShard { .. }
                | StealthUtxoFrame::Spent { .. }
                | StealthUtxoFrame::Burnt { .. } => {}
            }
        }
        // A pass that returns no shard at all means there is nothing left to drain.
        if !pass_progress {
            break;
        }
    }

    let crypto_api = StealthCryptoApi::new();
    for (id, utxo) in provider
        .fetch_unspent_utxos(ballot_resource, &fetch_keys)
        .await?
    {
        let commitment = id.into_commitment_bytes();
        let output = utxo
            .output()
            .context("ballot UTXO has been burnt since enumeration")?;
        let public_nonce: RistrettoPublicKey = output
            .output
            .public_nonce
            .try_from_byte_type()
            .expect("valid sender public nonce");
        let encryption_key = crypto_api.derive_encrypted_data_key(&public_nonce, view_secret);
        // Decryption validates the encrypted data's MAC: it succeeds only for the output
        // addressed to `view_secret`'s owner.
        if encrypted_data::unblind_output(
            &commitment,
            &output.output.encrypted_data,
            &encryption_key,
            true,
        )
        .is_ok()
        {
            return Ok((commitment, public_nonce));
        }
    }
    bail!("no unspent ballot UTXO owned by {voter_address} on resource {ballot_resource}")
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
    let tari_nonce: RistrettoPublicKey = tari_utxo
        .output
        .sender_public_nonce
        .try_from_byte_type()
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
        if let Some(w) = event.get_payload("winner") {
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

    let (component, ballot_resource, initiate_epoch) = create_and_initiate_vote(
        initiator_provider,
        template_address,
        &voter_addresses,
        num_candidates,
        num_winners,
        tally_method,
    )
    .await?;

    for (i, (wallet, voter_address, view_secret)) in voter_wallets.into_iter().enumerate() {
        println!("\n[Voter {i}] cast ballot ranking={:?}", ballots[i]);

        let mut voter_provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_with_transaction_timeout(
                default_indexer_url(network),
                Duration::from_secs(120),
            )
            .await?;

        // The voter discovers their own ballot UTXO by scanning the ballot resource — the
        // initiator sends nothing back after the vote is created. The scan is bounded to the
        // resource's history since the initiate transaction's commit epoch.
        let (ballot_commitment, ballot_nonce) = find_my_ballot_utxo(
            &voter_provider,
            &voter_address,
            &view_secret,
            ballot_resource,
            initiate_epoch,
        )
        .await?;
        println!(
            "  found own ballot UTXO: {}",
            hex::encode(ballot_commitment)
        );

        faucet(&mut voter_provider, &format!("Voter {i}")).await?;
        let (tari_commitment, tari_nonce) =
            convert_to_stealth_tari(&mut voter_provider, &voter_address).await?;
        cast_private_ballot(
            &mut voter_provider,
            component,
            ballot_resource,
            &voter_address,
            ballot_commitment,
            ballot_nonce,
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

    faucet(&mut initiator_provider, "Initiator").await?;
    let template_address = publish_template(&mut initiator_provider).await?;

    // Election 1: ranked-choice IRV (3 voters, 3 candidates, 1 winner).
    println!("\n=== Election 1: ranked-choice IRV ===");
    let irv_winner = run_election(
        &mut initiator_provider,
        template_address,
        VOTER_COUNT,
        NUM_CANDIDATES,
        NUM_WINNERS,
        TallyMethod::SequentialIrv,
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
