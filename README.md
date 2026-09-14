# Confidential Voting Template for Tari Ootle

> ## ⚠️ Minify the WASM before you publish
>
> ```bash
> cargo build --target wasm32-unknown-unknown --release -p ranked_voting
> wasm-opt -Oz --enable-bulk-memory \
>     target/wasm32-unknown-unknown/release/ranked_voting.wasm \
>     -o target/wasm32-unknown-unknown/release/ranked_voting.min.wasm
> ```
>
> Publish `ranked_voting.min.wasm` (~248 KB), never the raw `.wasm` (~287 KB). Publish fees
> scale with WASM size, and every validator stores the template forever — an unminified
> artifact costs roughly 15% more for the life of the chain.

A confidential ranked-choice voting template for the Tari Ootle L2 platform. Voters cast unlinkable ranked ballots using stealth-addressed ballot tokens — no on-chain observer can link any ballot transaction to the voter who cast it. The instant-runoff (IRV) tally is computed on-chain and is trustlessly readable by anyone. The same ballots also support **first-past-the-post (FPTP)** elections — covering plain plurality elections, yes/no votes (two candidates), and single-choice polls — chosen per election via `TallyMethod::Fptp`.

## Privacy model

This template inherits the **coinjoin-style blending** design from the sibling yes/no [confidential voting template](https://github.com/m4r1m0/confidential-voting-template) (obscure *who sent what ballot*, not the ballot content):

1. **Initiator mints stealth ballot tokens.** When a vote is initiated, the template mints one indivisible amount-1 ballot token per eligible voter and converts them into **stealth UTXOs** — each owned by a one-time key unlinkable to the voter's real public key. The stealth outputs are built off-chain by the initiator's wallet and passed to the template as a `StealthTransferStatement`. The supply is permanently capped at `voter_count` (see [Ballot supply cap](#ballot-supply-cap-no-extra-ballots)).

2. **Voters spend privately.** Each voter spends their stealth ballot-token UTXO via `cast_ballot`, attaching their full ranking of the candidates. Voters discover their own ballot UTXO by scanning the ballot resource's unspent outputs — the initiator sends nothing back after initiation (see [Voter UTXO discovery](#voter-utxo-discovery)). Because the spend is a **stealth transfer sealed with an ephemeral one-time key** (with the transaction fee paid from a separate stealth TARI UTXO), no on-chain observer can link the ballot transaction to a voter identity. The `cast_ballot` method deliberately never calls `CallerContext::transaction_signer_public_key()` so that ephemeral sealing works.

3. **Tally is public, on-chain, and trustless.** Anyone can call `result()` to compute the outcome from the stored ballots: instant-runoff for single-winner elections, first past the post when pinned to `TallyMethod::Fptp`, or the multi-winner method chosen at initiation (see below). The computation is deterministic, so every validator and off-chain reader agrees on the outcome.

### What is private vs. public

| Private (hidden) | Public (on-chain) |
|---|---|
| Voter identity (who cast which ballot) | Ballot content (each voter's full ranking) |
| | Number of ballots cast |
| | The winner and per-round tallies |

This is consistent with the [sibling template](https://github.com/m4r1m0/confidential-voting-template)'s model: voter *anonymity* is protected by stealth-address unlinkability; ballot *content* (the ranking) is visible on-chain. The ranking must be public for the on-chain IRV computation to be trustless.

### Double-vote prevention

Each voter receives exactly one indivisible amount-1 stealth token; the mint-statement invariants (below) force every ballot to be exactly one token at construction. A stealth UTXO can only be spent once — the engine enforces this at the consensus level — so a 1-token ballot cannot be split or cast twice.

### Ballot supply cap (no extra ballots)

The ballot supply is permanently capped at the initial `voter_count`; nobody — including the initiator — can mint additional ballots after the vote starts. The ballot resource's mint rule requires a proof of a **one-of NFT badge** ("RVOTE-MINT") that is created and sealed inside the component during `new()`:

- The badge's own mint/burn/recall rules are `deny_all` with locked updaters, so no second badge can ever exist and the sole copy can never be destroyed or recalled.
- The badge lives in a component vault that no template method exposes, so its proof can never be re-obtained. (Transactions cannot reach a vault directly: the transaction instruction set has no instruction that targets a vault address — see the `Instruction` enum in `tari_ootle_transaction` — so vaults are only reachable from within their owning component's method code.)
- The ballot resource is **ownerless** (`OwnerRule::None`), closing the resource-owner authorization path that would otherwise bypass the mint rule.
- The mint rule's updater is `LOCKED`, so the rule itself can never be changed.

The cap is verifiable by anyone: `voter_count()` returns the number of ballots minted, `ballot_vault_balance()` returns the number cast, and the ballot resource's total supply never exceeds `voter_count`.

### Mint-statement invariants

`new()` verifies three things about the mint statement it receives: its revealed input total equals `voter_count`, it creates exactly `voter_count` stealth outputs — one per voter — and every output promises a minimum value of at least one token. Each output's promise is public, and the engine's range-proof verification binds the output's committed value to be at least its promise; with `voter_count` outputs of at least one token each that sum to exactly `voter_count`, every ballot is forced to be exactly one token at construction. Wrong-valued shapes like `[2,0]` (a 2-token ballot plus a worthless 0-token output) are therefore unconstructible: a 0-value output can only ever be proven with a promise of 0, which the constructor rejects. Ballots can never be burned (`burnable` is `deny_all`), and no further ballots can be minted after the vote starts (see the supply cap above). The mint statement is a public argument of the initiating transaction, so scrutineers can audit exactly what was minted and to which addresses.

One limitation cannot be fixed in the template: nothing on-chain can verify that the minted outputs are distributed to *distinct* voters (two amount-1 ballots could be addressed to the same person, leaving another voter with none). Voter identity and ballot assignment are off-chain; the initiating transaction's public mint statement is the audit point for that.

### Fee-from-stealth requirement (MUST)

For a ballot to be truly unlinkable, the transaction fee must also be paid unlinkably. **Every ballot transaction MUST pay its fee from a stealth TARI UTXO.** Each voter converts revealed TARI into a stealth TARI UTXO first, then pays the ballot transaction's fee from that stealth UTXO (with change returned to another stealth UTXO).

Paying the fee from a revealed source breaks anonymity completely: the fee input links the transaction to the account owner, and because the ballot transaction itself carries the voter's full ranking, that link exposes not only *who voted* but *how they voted*. A revealed fee input effectively defeats the entire stealth mechanism.

The reference client in `client/integration` implements the canonical pattern in `cast_private_ballot`: a two-input stealth spend that uses the ballot-token UTXO as the seal input and a stealth TARI UTXO as the fee input, both bound to the same ephemeral one-time key. Wallet code that builds ballot transactions should follow that pattern exactly — the template cannot enforce it (it never sees fee inputs), so this requirement is a client-side contract.

Fees paid from a bucket (`pay_fee_from_bucket`) are **non-refundable**: the engine takes the revealed fee bucket in full and burns any excess to the fee pool — there is no refund destination that could link a ballot back to a revealed account. The reference client therefore reveals a flat `VOTE_FEE` per ballot that comfortably exceeds the actual fee; the overpay is deliberately uniform so every ballot transaction reveals the same fee.

### Voter UTXO discovery (scan, don't receive)

Voters do not receive their ballot UTXO's `(commitment, sender nonce)` from the initiator. The indexer enumerates a resource's unspent stealth UTXOs publicly (`watch_stealth_utxos` → `fetch_unspent_utxos` in `ootle-rs`), each resolved output carrying its commitment and the sender's public nonce. Every output's encrypted data is DH-encrypted to the recipient's view-only key, so a voter finds exactly their own ballot by attempting to decrypt each candidate output — the MAC check succeeds only for the one addressed to them. No secret material is exchanged; the only out-of-band step in the whole flow is voters providing their addresses to the initiator before `new()` so the mint statement can be addressed.

The reference client implements this in `find_my_ballot_utxo` (`client/integration/src/main.rs`). Like the fee-from-stealth requirement, it is a client-side contract: the template never sees UTXO commitments, and a wallet that was told its commitment instead of scanning produces a byte-identical ballot transaction.

## IRV tally algorithm (single-winner)

The single-winner tally uses **instant-runoff voting (IRV)**:

1. Count each ballot's highest-ranked **still-active** candidate as a vote for that candidate.
2. If any candidate has **strictly more than 50%** of the continuing ballots, they win.
3. Otherwise, **eliminate** the candidate with the fewest votes. Ties are broken by **lowest candidate id** (deterministic, so all validators agree).
4. Repeat until a winner is found or only one candidate remains.

If no ballots were cast, there is no winner: the tally returns `None` rather than electing anyone through elimination tie-breaks.

Each ballot is a permutation of `0..num_candidates`, where `ranking[0]` is the voter's first choice, `ranking[1]` their second, and so on. When a voter's top candidate is eliminated, their ballot redistributes to their next-highest-ranked still-active candidate.

The `result()` method is read-only (`&self`) and deterministic, so the outcome is trustless — no trusted tally authority is needed.

## FPTP tally algorithm (single-winner; yes/no and polling)

For plain plurality elections, yes/no votes, and single-choice polls, pin `TallyMethod::Fptp` in `new()` (with `num_winners = 1` — FPTP is single-winner by definition, and `new` rejects any other seat count):

1. Count each ballot's **first preference only** (`ranking[0]`) as a vote for that candidate. Later preferences never count.
2. The candidate with the **most votes** wins — no majority is required (a plurality suffices, unlike IRV).
3. Ties are broken by **lowest candidate id** (deterministic, so all validators agree).
4. If no ballots were cast, there is no winner: the tally returns `None`.

This covers three use cases with one method:

- **First-past-the-post elections** — any number of candidates; the plurality leader wins.
- **Yes/no voting** — exactly two candidates: candidate 0 = "yes", candidate 1 = "no". A ranking of `[0, 1]` is a yes vote, `[1, 0]` a no vote.
- **Polling** — any number of options; the most popular option wins.

Ballots are still full rankings (a permutation of `0..num_candidates`) — only the first preference matters, but every candidate must still be ranked. The privacy model is unchanged: the *choice* is public, the *voter* is hidden.

## Choosing the tally method

The tally method is **chosen once, when the vote is created**, by passing a `TallyMethod` to `new()`:

- `TallyMethod::Fptp` — **first past the post**, single-winner only (`num_winners` must be 1). See the FPTP section above.
- `TallyMethod::SequentialIrv` — the **default multi-winner** method: fill each seat by running single-winner IRV, removing the winner, and repeating. Simpler than STV (no quotas, no surplus transfer, no fractional weights) and reuses the single-winner logic directly. It is not proportional — a majority bloc could win all seats — but it is easy to audit and understand.
- `TallyMethod::Stv` — **single transferable vote** with the Droop quota for proportional representation.

The choice is stored in the component, so the outcome cannot be picked after the fact based on which method gives a favorable result. With `SequentialIrv`/`Stv`, `num_winners = 1` always uses plain IRV; `Fptp` always uses the first-preference tally.

## Sequential IRV tally algorithm (multi-winner, default)

For elections with multiple seats (e.g. council elections where seats are fungible), the **default multi-winner method** is sequential IRV:

1. Run single-winner IRV on all candidates to fill the first seat.
2. Remove the winner from all ballots (filter them out, preserving preference order).
3. Reindex remaining candidates to `0..N` and run IRV again to fill the next seat.
4. Repeat until all seats are filled or no candidates remain.

Sequential IRV is simpler than STV (no quotas, no surplus transfer, no fractional weights) and reuses the existing single-winner IRV logic directly. It is not proportional — a majority bloc could win all seats — but it is easy to audit and understand.

## STV tally algorithm (multi-winner, alternative)

For those who prefer proportional representation, the template also supports **single transferable vote (STV)** with the Droop quota as an alternative multi-winner method:

1. Compute the Droop quota: `floor(continuing_ballots / (num_winners + 1)) + 1`.
2. Count each ballot's highest-ranked still-active candidate, weighted by the ballot's current fractional weight (scaled by 10000 for fixed-point precision).
3. Any candidate reaching the quota is elected. Their surplus votes are transferred to those ballots' next preferences, with each ballot's weight scaled by `surplus / count`.
4. If no candidate reaches the quota, eliminate the lowest-count candidate (ties broken by lowest candidate id). Their ballots transfer at full weight to their next preference.
5. Repeat until all seats are filled or all remaining candidates fill the remaining seats.

## Election expiration

Elections have an `expires_at_epoch` deadline set at initiation. After the deadline, no more ballots may be cast (`cast_ballot` checks `Consensus::current_epoch()`). This prevents an election from being held up indefinitely by voters who never spend their stealth ballot tokens.

After expiration, `end_vote_expired()` finalizes the tally with whatever ballots were actually cast. It is callable by anyone, so the election cannot be held up by an initiator who never returns; the initiator can also use it. A zero-turnout election (deadline reached, no ballots cast) elects nobody.

## Template API

| Method | Access | Description |
|---|---|---|
| `new(alloc, voter_count, num_candidates, num_winners, tally_method, expires_at_epoch, mint_statement)` | — | Constructor. Creates the stealth ballot resource, mints per-voter stealth ballot UTXOs, seals the mint badge (permanently capping the supply at `voter_count`), and starts the vote — all in one transaction. `tally_method` pins the tally (`TallyMethod::Fptp` requires `num_winners = 1`). The caller of `new` is the **initiator**. |
| `resource_address()` | allow_all | Returns the ballot-token resource address. |
| `voter_count()` | allow_all | Returns the number of eligible voters (the ballot supply, which can never grow). |
| `cast_ballot(bucket, ranking)` | allow_all | Deposits one token + records a full ranking. Identity-free. Rejects after expiration. |
| `ballot_count()` | allow_all | Returns the number of ballots cast so far. |
| `ballot_vault_balance()` | allow_all | Returns the ballot pool vault balance (cross-check: equals `ballot_count`). |
| `result()` | allow_all | Computes the tally pinned in `new`: FPTP when `TallyMethod::Fptp`, IRV when `num_winners = 1`, otherwise the multi-winner `TallyMethod`. Read-only. Returns a `VoteResult`. |
| `end_vote()` | initiator-only | Ends the vote, returns the final `VoteResult`, locks further ballots. |
| `end_vote_expired()` | anyone (after the deadline) | Finalizes an expired election with the final `VoteResult` (even if not all ballots cast). |

The initiator is whoever called `new()` — no keys need to be edited before publishing. Only the initiator can end a live vote; anyone can finalize it once the deadline has passed, so an absent initiator cannot hold up finalization. Voter confidentiality does not depend on this gate (ballots are identity-free regardless); it exists so only the vote's creator can close it early.

## Project layout

```
tally/                           Pure tally algorithms (standalone crate `rcv-tally`)
  src/lib.rs                     FPTP + IRV + STV + sequential IRV; no template ABI dependency
templates/ranked_voting/         The template (Rust → WASM, pure cdylib)
  src/lib.rs                     Template; re-exports TallyMethod; wraps tally outputs into ABI result types
  tests/test.rs                  Unit + adversarial + end-to-end in-process tests (56)
client/integration/             IRV and FPTP yes/no elections end-to-end on the Esmeralda testnet; for primary testing see tests/test.rs, which covers the same scenarios in-process
```

## Build

```bash
# Compile the template to WASM (all methods)
cargo build --target wasm32-unknown-unknown --release -p ranked_voting

# Run the tests
cargo test -p ranked_voting

# Build the integration test client
cargo build --bin integration

> **wasmer pin:** `cargo test` needs `wasmer = "=7.3.0"` (pinned in
> `templates/ranked_voting/Cargo.toml`): `tari_engine` declares `wasmer ^7.1.0`, but
> wasmer 7.4.0 removed an API the engine uses. Remove the pins once tari-ootle
> tightens its wasmer constraint.
```

### Publishing

Minify the release build with [wasm-opt](https://github.com/WebAssembly/binaryen) before
publishing (see the notice at the top of this README):

```bash
wasm-opt -Oz --enable-bulk-memory \
    target/wasm32-unknown-unknown/release/ranked_voting.wasm \
    -o target/wasm32-unknown-unknown/release/ranked_voting.min.wasm
```

Publish `target/wasm32-unknown-unknown/release/ranked_voting.min.wasm`. The publish fee
scales with WASM size — unused fee is refunded (see `PUBLISH_FEE` in
`client/integration/src/main.rs`) — and a smaller artifact also downloads and instantiates
faster for voters.

The WASM includes all tally methods: FPTP plus single-winner IRV and both multi-winner methods
(sequential IRV and STV). Deployers pick the method per election via the `TallyMethod`
argument of `new()`; nothing needs to be recompiled or republished to change it.

## Run the integration test

First minify the template as shown above — the client publishes the minified artifact
(`target/wasm32-unknown-unknown/release/ranked_voting.min.wasm`).

```bash
cargo run --bin integration
```

This runs two elections on the Esmeralda testnet:

**Election 1 — ranked-choice IRV** (3 voters, 3 candidates, 1 winner):
- Initiator wallet faucets, publishes the template, creates the component with `new(3 candidates, 1 winner, sequential IRV, mint_statement)`, minting 3 stealth ballot UTXOs (one per voter).
- Three voter wallets each faucet, discover their own ballot UTXO by scanning the ballot resource, convert TARI to a stealth UTXO for fees, then cast a private ballot via a two-input stealth spend (ballot UTXO → `cast_ballot`, TARI UTXO → fee) with their ranking.
- `end_vote()` returns the IRV result: **candidate 2 wins in 2 rounds** (no first-round majority → candidate 0 eliminated → ballot redistributes to candidate 2 → majority).

**Election 2 — FPTP yes/no** (3 voters, 2 candidates = "yes"/"no", 1 winner):
- The same flow with `TallyMethod::Fptp`: voter choices are `[0, 1]` (yes), `[0, 1]` (yes), `[1, 0]` (no).
- `end_vote()` returns the FPTP result: **candidate 0 ("yes") wins 2–1** — a plurality, no majority required.
