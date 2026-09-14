use tari_template_lib::prelude::*;

/// The tally algorithm used for an election. Chosen once at contract initialization and stored
/// in the component, so the outcome cannot be picked after the fact based on which method gives
/// a more favorable result.
///
/// `Fptp` is single-winner only; `SequentialIrv` and `Stv` are multi-winner methods
/// (`num_winners > 1`) — with `num_winners == 1` they fall back to plain IRV.
///
/// Defined in the standalone `rcv-tally` crate (see its docs) and re-exported here so the
/// template macro's dispatcher — which decodes function arguments at crate scope — can resolve
/// it without linking an rlib of this crate.
pub use rcv_tally::TallyMethod;

/// A vote instance mints one unlinkable stealth ballot-token UTXO per eligible voter (built
/// off-chain by the initiator's wallet and passed in as a `StealthTransferStatement`). Each voter
/// spends their UTXO into the ballot pool via `cast_ballot`, attaching a full ranking of the
/// candidates (a permutation of `0..num_candidates`). Because the spend is a stealth transfer
/// sealed with an ephemeral key (fee paid from a stealth TARI UTXO), no on-chain observer can link
/// any vote transaction to a voter. The ranking itself is public on-chain; only voter *identity*
/// is hidden (consistent with the sibling confidential-voting template's privacy model: obscure
/// *who*, not *what*).
///
/// The tally is instant-runoff: count each ballot's highest-ranked still-active candidate; if one
/// exceeds 50% they win; otherwise eliminate the lowest-count candidate (elimination ties
/// broken by lowest candidate id for determinism) and repeat. A tie between the final two
/// candidates — like zero turnout, the degenerate tie — yields no winner (`None`), so a tied
/// election must be re-run. Elections pinned to `TallyMethod::Fptp` instead
/// count first preferences only (single-winner plurality — see the `new` docs), which covers
/// plain FPTP elections, yes/no votes (two candidates), and single-choice polls; an FPTP tie
/// for the most votes likewise yields no winner. `result()` is
/// a deterministic computation over the stored ballots, so the outcome is trustless — any
/// validator or off-chain reader computes the same winner.
///
/// Double-voting is impossible: the mint statement's per-output minimum-value promises (asserted
/// in `new` and bound by the engine's range proof) pin every ballot to exactly one token at
/// construction, and a stealth UTXO can only be spent once.
///
/// The ballot supply is also permanently capped: minting ballot tokens requires a proof of a
/// one-of NFT badge that is sealed inside the component at construction. After the vote starts,
/// nobody — including the initiator — can mint additional ballots. The ballot resource is
/// ownerless (`OwnerRule::None`), so the resource-owner authorization path cannot be used to
/// bypass the mint rule either.
#[template]
pub mod ranked_voting {
    use super::*;
    use rcv_tally::fptp::run_fptp;
    use rcv_tally::irv::run_irv;
    use rcv_tally::sequential_irv::run_sequential_irv;
    use rcv_tally::stv::run_stv;
    use std::collections::{BTreeMap, BTreeSet};

    pub struct RankedVote {
        ballot_resource: ResourceAddress,
        /// Resource holding the single one-of mint badge that authorizes minting ballot tokens.
        mint_badge_resource: ResourceAddress,
        /// Sealed vault holding the sole mint badge. The badge's mint/burn/recall rules are
        /// `deny_all` with locked updaters and no template method exposes this vault, so the
        /// ballot supply is permanently capped at `voter_count`.
        mint_badge_vault: Vault,
        /// Persistent sink for spent ballot tokens. Its balance equals the number of ballots cast
        /// (each ballot is an indivisible amount-1 token), providing a trustless cross-check of
        /// `ballots.len()`.
        ballot_vault: Vault,
        ballots: Vec<Vec<u32>>,
        num_candidates: u32,
        /// Number of winners to elect. 1 = single-winner IRV (or FPTP when `TallyMethod::Fptp`);
        /// >1 = multi-winner via the method chosen in `new` (`TallyMethod`).
        num_winners: u32,
        /// The tally algorithm used for the election, pinned once at construction; the outcome
        /// cannot later be picked from whichever method is favorable.
        tally_method: TallyMethod,
        /// The number of eligible voters: the ballot supply minted at construction. The supply
        /// can never grow after construction (see `mint_badge_vault`).
        voter_count: u64,
        /// The epoch after which no more ballots may be cast. Prevents elections from being held
        /// up indefinitely by voters who never spend their stealth ballot tokens.
        expires_at_epoch: u64,
        active: bool,
    }

    /// The result of a tally, returned by `result()` / `end_vote()` / `end_vote_expired()`.
    ///
    /// The variant is fixed by the election's configuration: `TallyMethod::Fptp` always yields
    /// `Fptp`; `num_winners == 1` yields `Irv`; and multi-winner elections yield whichever
    /// variant the `TallyMethod` chosen at initialization produces.
    #[derive(Clone, Debug)]
    pub enum VoteResult {
        /// Single-winner instant-runoff result.
        Irv(IrvResult),
        /// First-past-the-post single-winner result.
        Fptp(FptpResult),
        /// Sequential-IRV multi-winner result.
        SequentialIrv(SequentialIrvResult),
        /// STV multi-winner result.
        Stv(StvResult),
    }

    /// Result of an instant-runoff tally.
    #[derive(Clone, Debug)]
    pub struct IrvResult {
        /// The winning candidate id, or `None` if no winner could be determined.
        pub winner: Option<u32>,
        /// Per-round tally: counts of first-preference-among-active candidates, and which
        /// candidate was eliminated that round (`None` on the final, deciding round).
        pub rounds: Vec<RoundTally>,
    }

    /// One round of the instant-runoff tally.
    #[derive(Clone, Debug)]
    pub struct RoundTally {
        /// First-preference counts among still-active candidates in this round.
        pub counts: BTreeMap<u32, u64>,
        /// The candidate eliminated at the end of this round, or `None` on the deciding round.
        pub eliminated: Option<u32>,
    }

    /// Result of a single-transferable-vote (multi-winner) tally.
    #[derive(Clone, Debug)]
    pub struct StvResult {
        /// The winning candidate ids, in the order they were elected.
        pub winners: Vec<u32>,
        /// Per-round tally trace.
        pub rounds: Vec<StvRoundTally>,
    }

    /// Result of a first-past-the-post tally. With exactly two candidates this is a plain
    /// yes/no vote; with more it is a single-choice poll.
    #[derive(Clone, Debug)]
    pub struct FptpResult {
        /// The winning candidate id (most first-preference votes), or `None` if no ballots
        /// were cast or the most-vote count is shared (a tie — including zero turnout,
        /// the degenerate tie where every count is 0).
        pub winner: Option<u32>,
        /// First-preference counts per candidate.
        pub counts: BTreeMap<u32, u64>,
    }

    /// One round of the STV tally.
    #[derive(Clone, Debug)]
    pub struct StvRoundTally {
        /// Vote counts (scaled) for each still-active candidate in this round.
        pub counts: BTreeMap<u32, u64>,
        /// Candidates elected in this round (reached the quota).
        pub elected: Vec<u32>,
        /// The candidate eliminated in this round, if any.
        pub eliminated: Option<u32>,
        /// The Droop quota threshold used this round.
        pub quota: u64,
    }

    /// Result of a sequential-IRV (multi-winner) tally. This is the default multi-winner method.
    #[derive(Clone, Debug)]
    pub struct SequentialIrvResult {
        /// The winning candidate ids, in the order they were elected.
        pub winners: Vec<u32>,
        /// Per-seat tally trace: one entry per seat, containing the winner and the IRV
        /// sub-rounds that elected them.
        pub seats: Vec<SequentialRoundTally>,
    }

    /// One seat's election in the sequential-IRV tally.
    #[derive(Clone, Debug)]
    pub struct SequentialRoundTally {
        /// The candidate who won this seat, or `None` if no winner could be determined.
        pub winner: Option<u32>,
        /// The IRV sub-rounds for this seat's election (same format as `RoundTally`).
        pub irv_rounds: Vec<RoundTally>,
    }

    impl RankedVote {
        /// Constructor — creates the component, the stealth ballot resource, and starts the vote
        /// in a single transaction.
        ///
        /// # Parameters
        ///
        /// - `alloc`: Pre-allocated resource address. The caller allocates this before the
        ///   transaction so the `mint_statement` can reference it. The resource is created inside
        ///   this call with `with_address_allocation(alloc)`.
        /// - `voter_count`: Number of eligible voters. One stealth ballot UTXO is minted per
        ///   voter.
        /// - `num_candidates`: Number of candidates. Each ballot must be a permutation of
        ///   `0..num_candidates`.
        /// - `num_winners`: Number of seats to fill. 1 = single-winner IRV (or FPTP when
        ///   `TallyMethod::Fptp`); >1 = multi-winner via `tally_method`.
        /// - `tally_method`: The tally algorithm for the election, pinned here and stored in the
        ///   component, so the outcome cannot be picked after the fact based on whichever method
        ///   gives a favorable result. `Fptp` is single-winner only (`num_winners` must be 1);
        ///   `SequentialIrv`/`Stv` apply when `num_winners > 1` and fall back to plain IRV for
        ///   single-winner elections.
        /// - `expires_at_epoch`: Deadline after which no more ballots may be cast. Prevents
        ///   elections from being held up indefinitely by voters who never spend their stealth
        ///   ballot tokens. After expiration, `end_vote_expired()` finalizes the tally with
        ///   whatever ballots were cast.
        /// - `mint_statement`: Built off-chain by the initiator's wallet. Must carry exactly
        ///   `voter_count` as its revealed input amount and exactly `voter_count` stealth
        ///   outputs, one per voter — both asserted below — and each output must promise a
        ///   minimum value of at least one token (also asserted below). Because the engine's
        ///   range proof binds every committed output value to be at least its promise, the
        ///   total, output-count, and per-output promise checks together force every ballot to
        ///   be exactly one token at construction; the cast-time `amount == 1` guard remains
        ///   as defense in depth.
        ///
        /// The caller of `new` is the initiator: before the deadline only they may end the vote;
        /// after the deadline anyone may finalize it. No template fields need to be edited before
        /// publishing — the initiator's key is captured from the transaction here, and the ballot
        /// supply is permanently capped at `voter_count`: the mint rule of the ballot resource
        /// requires a proof of a one-of badge that is sealed in the component by this call, so no
        /// further ballots can ever be minted.
        pub fn new(
            alloc: ResourceAddressAllocation,
            voter_count: u64,
            num_candidates: u32,
            num_winners: u32,
            tally_method: TallyMethod,
            expires_at_epoch: u64,
            mint_statement: StealthTransferStatement,
        ) -> Component<Self> {
            assert!(voter_count > 0, "voter_count must be positive");
            assert!(num_candidates > 0, "num_candidates must be positive");
            assert!(num_winners > 0, "num_winners must be positive");
            assert!(
                num_winners <= num_candidates,
                "num_winners cannot exceed num_candidates",
            );
            // FPTP is single-winner by definition: it counts first preferences only, so multiple
            // seats would be indistinguishable from sequential plurality rather than a tally.
            assert!(
                !matches!(tally_method, TallyMethod::Fptp) || num_winners == 1,
                "TallyMethod::Fptp is single-winner only (num_winners must be 1)",
            );
            assert_eq!(
                mint_statement.revealed_input_amount(),
                Amount::from(voter_count),
                "mint statement revealed input must equal voter_count",
            );
            // One stealth output per voter (see the `mint_statement` doc comment above).
            assert_eq!(
                mint_statement.stealth_outputs().len() as u64,
                voter_count,
                "mint statement must create one stealth output per voter",
            );
            // Every output must promise a minimum value of one token. Each output's promise is
            // public and the engine's range-proof verification binds the output's committed value
            // to be at least its promise. So with `voter_count` outputs of at least one token each
            // that sum to exactly `voter_count`, no output can hold zero or more than one token:
            // every ballot is exactly one token at construction. The cast-time `amount == 1`
            // guard remains as defense in depth.
            for output in mint_statement.stealth_outputs() {
                assert!(
                    output.output.minimum_value_promise >= 1,
                    "each ballot output must promise a minimum value of 1",
                );
            }

            // The caller of `new` is the initiator: their key gates ending the vote before the
            // deadline. Capturing the key here instead of hard-coding placeholders means nothing
            // needs to be edited before publishing.
            let initiator = CallerContext::transaction_signer_public_key();

            // The ballot resource's mint rule requires a proof of a one-of NFT badge that is
            // sealed in `mint_badge_vault` when the component is created. The badge authorizes
            // the ballot mint inside this constructor only. The badge's mint/burn/recall rules
            // are deny_all with locked updaters (no second badge can ever exist, and the sole
            // copy can never be destroyed or recalled); its withdraw rule must stay allow_all
            // because creating the constructor's proof is authorized under it (the engine checks
            // `BucketAction::CreateProof` against the Withdraw access rule) — but the rule is
            // inert after construction: the transaction instruction set has no instruction that
            // targets a vault address (see the `Instruction` enum in `tari_ootle_transaction`),
            // so vaults are reachable only from within their owning component's method code,
            // and no template method ever exposes `mint_badge_vault`. The ballot resource is
            // ownerless, so the ballot supply is permanently capped at `voter_count`.
            let badge_bucket = ResourceBuilder::non_fungible()
                .with_token_symbol("RVOTE-MINT")
                .with_owner_rule(OwnerRule::None)
                .mintable(rule!(deny_all), LOCKED)
                .burnable(rule!(deny_all), LOCKED)
                .recallable(rule!(deny_all), LOCKED)
                .withdrawable(rule!(allow_all), LOCKED)
                .update_non_fungible_data(rule!(deny_all), LOCKED)
                .initial_supply_with_data(vec![(NonFungibleId::from_u64(0), (&metadata![], &()))]);
            let mint_badge_resource = badge_bucket.resource_address();

            let ballot_resource = ResourceBuilder::stealth()
                .with_token_symbol("RVOTE")
                .with_divisibility(0)
                .with_owner_rule(OwnerRule::None)
                .mintable(rule!(resource(mint_badge_resource)), LOCKED)
                .burnable(rule!(deny_all), LOCKED)
                .with_address_allocation(alloc)
                .build();

            // Mint voter_count revealed tokens and convert them into per-voter stealth UTXOs
            // via the caller-provided mint statement. Any revealed output (which there should
            // not be) is dropped — the mint is fully converted to stealth outputs. The proof
            // is dropped (releasing its lock on the badge) so the badge can be sealed in the
            // component.
            let mint_proof = badge_bucket.create_proof();
            let manager = ResourceManager::get(ballot_resource);
            let minted = manager.mint_stealth(Amount::from(voter_count));
            let _revealed_out =
                manager.stealth_transfer_with_opt_input_bucket(mint_statement, Some(minted));
            mint_proof.drop();

            Component::new(Self {
                ballot_resource,
                mint_badge_resource,
                mint_badge_vault: Vault::from_bucket(badge_bucket),
                ballot_vault: Vault::new_empty(ballot_resource),
                ballots: Vec::new(),
                num_candidates,
                num_winners,
                tally_method,
                voter_count,
                expires_at_epoch,
                active: true,
            })
            .with_access_rules(
                AccessRules::new()
                    // Initiator-only: the caller of `new` is the initiator, and their key (see
                    // above) is the only one that may end a live vote. After the deadline anyone
                    // may finalize via `end_vote_expired`, so an absent initiator cannot hold up
                    // finalization. Voter confidentiality does not depend on this gate — even a
                    // compromised initiator key cannot inflate the ballot supply, which the
                    // sealed mint badge caps.
                    .method("end_vote", rule!(public_key(initiator)))
                    .method("end_vote_expired", rule!(allow_all))
                    // cast_ballot / result / ballot_count / resource_address are callable by
                    // anyone; they deliberately do NOT call
                    // CallerContext::transaction_signer_public_key() so that voters' transactions
                    // can be sealed with an ephemeral key (no identity).
                    .method("cast_ballot", rule!(allow_all))
                    .method("result", rule!(allow_all))
                    .method("ballot_count", rule!(allow_all))
                    .method("ballot_vault_balance", rule!(allow_all))
                    .method("voter_count", rule!(allow_all))
                    .method("resource_address", rule!(allow_all))
                    .default(rule!(deny_all)),
            )
            .create()
        }

        /// The ballot-token resource address (so the initiator can build outputs for it).
        pub fn resource_address(&self) -> ResourceAddress {
            self.ballot_resource
        }

        /// The number of eligible voters: the ballot supply minted at construction. The supply
        /// can never grow after construction (the ballot resource's mint rule requires a proof of
        /// a badge that is sealed in this component), so this is a hard cap on the number of
        /// ballots that can ever be cast.
        pub fn voter_count(&self) -> u64 {
            self.voter_count
        }

        /// Deposit a revealed ballot-token bucket and record the voter's full ranking. `ranking`
        /// must be a permutation of `0..num_candidates`, where `ranking[0]` is the voter's first
        /// choice, `ranking[1]` their second, and so on. This method deliberately does not call
        /// `CallerContext::transaction_signer_public_key()` so the ballot transaction can be
        /// sealed with an ephemeral one-time key (no voter identity).
        pub fn cast_ballot(&mut self, bucket: Bucket, ranking: Vec<u32>) {
            assert!(self.active, "No active vote");
            let current_epoch = Consensus::current_epoch();
            assert!(
                current_epoch <= self.expires_at_epoch,
                "Voting period has expired (current epoch {current_epoch}, deadline {})",
                self.expires_at_epoch,
            );
            assert_eq!(
                bucket.resource_address(),
                self.ballot_resource,
                "bucket must be the ballot resource",
            );
            assert!(
                bucket.amount() == Amount::from(1u64),
                "each ballot must be exactly one token",
            );
            self.validate_ranking(&ranking);

            self.ballots.push(ranking);
            // The bucket is consumed by deposit into the persistent ballot pool. The token is
            // provably spent (single-spend enforced by the engine); the vault balance equals the
            // number of ballots cast.
            self.ballot_vault.deposit(bucket);
            emit_event(
                "BallotCast",
                metadata!["ballots" => self.ballots.len().to_string()],
            );
        }

        /// Number of ballots cast so far.
        pub fn ballot_count(&self) -> u64 {
            self.ballots.len() as u64
        }

        /// Balance of the ballot pool vault (equals ballot_count — a trustless cross-check).
        pub fn ballot_vault_balance(&self) -> Amount {
            self.ballot_vault.balance()
        }

        /// Compute the tally for the configured election: FPTP when `TallyMethod::Fptp` was pinned in
        /// `new`, single-winner IRV when `num_winners == 1`, otherwise the multi-winner method
        /// pinned in `new` (`TallyMethod`). Read-only and deterministic.
        pub fn result(&self) -> VoteResult {
            match self.tally_method {
                TallyMethod::Fptp => VoteResult::Fptp(self.fptp_result()),
                TallyMethod::SequentialIrv if self.num_winners > 1 => {
                    VoteResult::SequentialIrv(self.sequential_irv_result())
                }
                TallyMethod::Stv if self.num_winners > 1 => VoteResult::Stv(self.stv_result()),
                // SequentialIrv / Stv with a single winner fall back to plain IRV.
                TallyMethod::SequentialIrv | TallyMethod::Stv => VoteResult::Irv(self.irv_result()),
            }
        }

        /// Single-winner instant-runoff tally. Emits a `Result` event.
        fn irv_result(&self) -> IrvResult {
            let (winner, rounds) = run_irv(&self.ballots, self.num_candidates);
            let rounds: Vec<RoundTally> = rounds
                .into_iter()
                .map(|round| RoundTally {
                    counts: round.counts,
                    eliminated: round.eliminated,
                })
                .collect();
            let result = IrvResult { winner, rounds };
            emit_event(
                "Result",
                metadata![
                    "winner" => match result.winner {
                        Some(w) => w.to_string(),
                        None => "none".to_string(),
                    },
                    "rounds" => result.rounds.len().to_string(),
                ],
            );
            result
        }

        /// First-past-the-post single-winner tally: counts each ballot's first preference; the
        /// candidate with the most votes wins (no majority required). A tie for the most votes
        /// has no winner, exactly like zero turnout (the degenerate tie). With exactly two
        /// candidates this is a plain yes/no vote. Emits a `ResultFptp` event.
        fn fptp_result(&self) -> FptpResult {
            let (winner, counts) = run_fptp(&self.ballots, self.num_candidates);
            let result = FptpResult { winner, counts };
            emit_event(
                "ResultFptp",
                metadata![
                    "winner" => match result.winner {
                        Some(w) => w.to_string(),
                        None => "none".to_string(),
                    },
                    "counts" => format!("{:?}", result.counts),
                ],
            );
            result
        }

        /// Sequential-IRV multi-winner tally. Emits a `ResultMulti` event.
        fn sequential_irv_result(&self) -> SequentialIrvResult {
            let (winners, seats) =
                run_sequential_irv(&self.ballots, self.num_candidates, self.num_winners);
            let seats: Vec<SequentialRoundTally> = seats
                .into_iter()
                .map(|seat| SequentialRoundTally {
                    winner: seat.winner,
                    irv_rounds: seat
                        .irv_rounds
                        .into_iter()
                        .map(|irv_round| RoundTally {
                            counts: irv_round.counts,
                            eliminated: irv_round.eliminated,
                        })
                        .collect(),
                })
                .collect();
            let result = SequentialIrvResult { winners, seats };
            emit_event(
                "ResultMulti",
                metadata![
                    "winners" => format!("{:?}", result.winners),
                    "seats" => result.seats.len().to_string(),
                ],
            );
            result
        }

        /// STV multi-winner tally. Emits a `ResultStv` event.
        fn stv_result(&self) -> StvResult {
            let (winners, rounds) = run_stv(&self.ballots, self.num_candidates, self.num_winners);
            let rounds: Vec<StvRoundTally> = rounds
                .into_iter()
                .map(|round| StvRoundTally {
                    counts: round.counts,
                    elected: round.elected,
                    eliminated: round.eliminated,
                    quota: round.quota,
                })
                .collect();
            let result = StvResult { winners, rounds };
            emit_event(
                "ResultStv",
                metadata![
                    "winners" => format!("{:?}", result.winners),
                    "rounds" => result.rounds.len().to_string(),
                ],
            );
            result
        }

        /// End the vote (initiator-only). Locks the vote against further ballots and returns the
        /// tally for the configured election: FPTP when `TallyMethod::Fptp`, single-winner IRV
        /// when `num_winners == 1`, otherwise the multi-winner method pinned in `new`.
        pub fn end_vote(&mut self) -> VoteResult {
            assert!(self.active, "No active vote");
            self.active = false;
            let result = self.result();
            emit_event(
                "VoteEnded",
                metadata!["ballots_cast" => self.ballots.len().to_string()],
            );
            result
        }

        /// End the vote after the voting period has expired (callable by anyone), even if not
        /// all eligible voters cast ballots. This prevents an election from being held up
        /// indefinitely by non-voting participants — or by an initiator who never returns to
        /// finalize it. The tally is computed with whatever ballots were actually cast, using
        /// the same dispatch as `end_vote`.
        pub fn end_vote_expired(&mut self) -> VoteResult {
            assert!(self.active, "No active vote");
            let current_epoch = Consensus::current_epoch();
            assert!(
                current_epoch > self.expires_at_epoch,
                "Voting period has not yet expired (current epoch {current_epoch}, deadline {})",
                self.expires_at_epoch,
            );
            self.active = false;
            let result = self.result();
            emit_event(
                "VoteEndedExpired",
                metadata!["ballots_cast" => self.ballots.len().to_string()],
            );
            result
        }

        /// Asserts `ranking` is a valid permutation of `0..num_candidates`.
        fn validate_ranking(&self, ranking: &[u32]) {
            assert_eq!(
                ranking.len(),
                self.num_candidates as usize,
                "ranking must list every candidate exactly once",
            );
            let mut seen: BTreeSet<u32> = BTreeSet::new();
            for &c in ranking {
                assert!(c < self.num_candidates, "candidate id {c} out of range");
                assert!(seen.insert(c), "candidate {c} ranked twice");
            }
        }
    }
}
