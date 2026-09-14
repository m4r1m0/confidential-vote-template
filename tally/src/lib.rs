//! Pure deterministic tally algorithms for ranked-choice elections: instant-runoff voting
//! (IRV), first past the post (FPTP), single transferable vote (STV), and sequential IRV for
//! multi-winner seats.
//!
//! These live in a standalone crate so that (a) they can be unit-tested without linking the
//! template itself — letting the template ship as a pure cdylib, which unlocks full LTO and
//! a ~20% smaller WASM (with both `cdylib` and `rlib` crate-types, rustc silently drops
//! `-C lto`) — and (b) the algorithms carry no template ABI dependency; the template's
//! `result()` methods wrap these outputs into ABI-compatible structs.

use minicbor::{Decode, Encode};
use std::collections::BTreeMap;

/// The tally algorithm used for an election. Chosen once at contract initialization and stored
/// in the component, so the outcome cannot be picked after the fact based on which method gives
/// a more favorable result.
///
/// `Fptp` is single-winner only; `SequentialIrv` and `Stv` are multi-winner methods
/// (`num_winners > 1`). With `SequentialIrv` or `Stv` and `num_winners == 1`, the tally falls
/// back to plain single-winner IRV.
///
/// Defined here (rather than in the template) so tests can construct it without linking the
/// template crate; the template re-exports it at its crate root, keeping the on-chain ABI
/// unchanged — the dispatcher decodes arguments structurally via these CBOR derives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, minicbor::CborLen)]
pub enum TallyMethod {
    /// Fill each seat by running single-winner IRV, removing the winner, and repeating.
    #[n(0)]
    SequentialIrv,
    /// Single transferable vote with the Droop quota (proportional representation).
    #[n(1)]
    Stv,
    /// First past the post: single-winner only (`num_winners == 1`). Counts each ballot's first
    /// preference; the candidate with the most votes wins (no majority required). With exactly
    /// two candidates this is a plain yes/no vote, and with more it is a single-choice poll.
    #[n(2)]
    Fptp,
}

/// The candidate with a strictly unique, positive maximum count, or `None` when the maximum is
/// shared (a tie) or zero (zero turnout — the degenerate tie where every count is 0). Both
/// cases yield no winner, so ties and zero turnout are decided by the same function.
pub fn unique_plurality_winner(counts: &BTreeMap<u32, u64>) -> Option<u32> {
    let max = *counts.values().max()?;
    if max == 0 {
        return None;
    }
    let mut tied = counts.iter().filter(|&(_, &v)| v == max);
    let winner = tied.next()?;
    if tied.next().is_some() {
        None
    } else {
        Some(*winner.0)
    }
}

/// Pure instant-runoff tally logic, isolated from the template engine so it can be unit-tested
/// directly without stealth-transfer machinery. Returns simple types (winner + per-round data) so
/// it has no dependency on template ABI traits; the template's `result()` method wraps the output
/// into the ABI-compatible `IrvResult` struct.
pub mod irv {
    use super::unique_plurality_winner;
    use std::collections::{BTreeMap, BTreeSet};

    /// Per-round data: first-preference counts among active candidates, and which candidate was
    /// eliminated that round (`None` on the deciding round).
    pub struct Round {
        pub counts: BTreeMap<u32, u64>,
        pub eliminated: Option<u32>,
    }

    /// Instant-runoff tally over a set of ballots. Each ballot is a permutation of
    /// `0..num_candidates` ordered by preference (index 0 = first choice). Deterministic: ties
    /// for elimination (multiple candidates tied for the lowest count) are broken by lowest
    /// candidate id — the procedural rule used by real IRV jurisdictions — so all validators
    /// agree on the outcome. A tie for the *winner* (the final two candidates tied) has no
    /// winner, exactly like zero turnout: both return `None`, and the election must be re-run.
    ///
    /// Returns `(winner, rounds)` where `winner` is `Some(candidate_id)` or `None`, and `rounds`
    /// is the per-round tally trace. An election with no continuing ballots (e.g. zero turnout)
    /// has no winner: returns `None` rather than crowning a candidate by elimination tie-breaks.
    pub fn run_irv(ballots: &[Vec<u32>], num_candidates: u32) -> (Option<u32>, Vec<Round>) {
        let mut active: BTreeSet<u32> = (0..num_candidates).collect();
        let mut rounds: Vec<Round> = Vec::new();

        loop {
            // Count each ballot's highest-ranked still-active candidate.
            let mut counts: BTreeMap<u32, u64> = active.iter().map(|&c| (c, 0u64)).collect();
            let mut total: u64 = 0;
            for ballot in ballots {
                for &c in ballot {
                    if active.contains(&c) {
                        *counts.get_mut(&c).expect("active candidate counted") += 1;
                        total += 1;
                        break;
                    }
                }
            }

            // No continuing ballots (e.g. zero turnout): nobody voted, so there is no winner.
            // Return before the elimination tie-breaks could crown an arbitrary candidate.
            if total == 0 {
                rounds.push(Round {
                    counts,
                    eliminated: None,
                });
                return (None, rounds);
            }

            // Majority: strictly more than half of continuing ballots.
            let mut majority_winner: Option<u32> = None;
            for (&c, &v) in &counts {
                if v * 2 > total {
                    majority_winner = Some(c);
                    break;
                }
            }
            if let Some(w) = majority_winner {
                rounds.push(Round {
                    counts,
                    eliminated: None,
                });
                return (Some(w), rounds);
            }

            // Exactly two candidates remain: the majority check above already returned a winner
            // unless the remaining two are tied, so this resolves a final-round tie with the
            // same shared unique-winner check — no winner, exactly like zero turnout.
            if active.len() == 2 {
                let winner = unique_plurality_winner(&counts);
                rounds.push(Round {
                    counts,
                    eliminated: None,
                });
                return (winner, rounds);
            }

            // Eliminate the lowest-count candidate; ties broken by lowest id (BTreeSet order).
            let min_count = *counts.values().min().expect("non-empty active set");
            let to_eliminate = active
                .iter()
                .copied()
                .find(|c| counts.get(c) == Some(&min_count))
                .expect("an elimination candidate exists");
            active.remove(&to_eliminate);
            rounds.push(Round {
                counts,
                eliminated: Some(to_eliminate),
            });
        }
    }
}

/// Pure single-transferable-vote (STV) tally logic for multi-winner elections, isolated from the
/// template engine so it can be unit-tested directly. Returns simple types (winners + per-round
/// data) with no dependency on template ABI traits.
pub mod stv {
    use std::collections::{BTreeMap, BTreeSet};

    /// Scale factor for fractional vote values. STV surplus transfers require fractional votes
    /// (a candidate's surplus is distributed proportionally to their voters' next preferences).
    /// We use fixed-point arithmetic with this scale to stay integer-only and deterministic for
    /// consensus. 10000 gives 4 decimal places of precision.
    const VOTE_SCALE: u64 = 10_000;

    /// One ballot's weighted vote. Each ballot starts with weight 1.0 (= VOTE_SCALE) and its
    /// weight is reduced fractionally when its chosen candidate is elected with a surplus.
    struct WeightedBallot {
        ranking: Vec<u32>,
        weight: u64,
    }

    /// Per-round data for the STV tally trace.
    pub struct Round {
        /// Vote counts (scaled) for each still-active candidate in this round.
        pub counts: BTreeMap<u32, u64>,
        /// Candidates elected in this round (reached the quota).
        pub elected: Vec<u32>,
        /// The candidate eliminated in this round, if any.
        pub eliminated: Option<u32>,
        /// The quota threshold used this round.
        pub quota: u64,
    }

    /// Single-transferable-vote tally with the Droop quota. Each ballot is a permutation of
    /// `0..num_candidates` ordered by preference. Returns `(winners, rounds)`.
    ///
    /// Algorithm:
    /// 1. Compute the Droop quota: `floor(continuing_ballots / (num_winners + 1)) + 1`.
    /// 2. Count each ballot's highest-ranked still-active candidate, weighted by the ballot's
    ///    current fractional weight.
    /// 3. Any candidate reaching the quota is elected. Their surplus votes (count - quota) are
    ///    transferred to those ballots' next preferences, with each ballot's weight scaled by
    ///    `surplus / count`.
    /// 4. If no candidate reaches the quota, eliminate the lowest-count candidate (ties broken
    ///    by lowest candidate id for determinism). Their ballots transfer at full weight to their
    ///    next preference.
    /// 5. Repeat until all seats are filled or all remaining candidates fill the remaining seats.
    ///
    /// An election with no continuing ballots (e.g. zero turnout) elects nobody: the count stops
    /// with only the candidates elected so far (none on a fresh tally).
    ///
    /// Deterministic: all validators agree on the outcome.
    pub fn run_stv(
        ballots: &[Vec<u32>],
        num_candidates: u32,
        num_winners: u32,
    ) -> (Vec<u32>, Vec<Round>) {
        let mut active: BTreeSet<u32> = (0..num_candidates).collect();
        let mut elected: Vec<u32> = Vec::new();
        let mut rounds: Vec<Round> = Vec::new();

        // Each ballot starts with full weight (1.0 in scaled fixed-point).
        let mut weighted_ballots: Vec<WeightedBallot> = ballots
            .iter()
            .map(|ranking| WeightedBallot {
                ranking: ranking.clone(),
                weight: VOTE_SCALE,
            })
            .collect();

        loop {
            // All seats filled — done.
            if elected.len() >= num_winners as usize {
                break;
            }

            // Remaining active candidates all get seats (fewer candidates than remaining seats).
            if active.len() <= num_winners as usize - elected.len() {
                for &candidate in active.iter() {
                    elected.push(candidate);
                }
                break;
            }

            // Count weighted votes for each active candidate.
            let mut counts: BTreeMap<u32, u64> = active.iter().map(|&c| (c, 0u64)).collect();
            let mut total_continuing: u64 = 0;
            for ballot in &weighted_ballots {
                for &candidate in &ballot.ranking {
                    if active.contains(&candidate) {
                        *counts
                            .get_mut(&candidate)
                            .expect("active candidate counted") += ballot.weight;
                        total_continuing += ballot.weight;
                        break;
                    }
                }
            }

            // No continuing ballots (e.g. zero turnout): stop without electing anyone. Without
            // this, the quota below computes to 0 and every candidate would satisfy it.
            if total_continuing == 0 {
                break;
            }

            // Droop quota: floor(continuing / (seats + 1)) + 1, in scaled units.
            let remaining_seats = num_winners as u64 - elected.len() as u64;
            // total_continuing > 0 here (zero-turnout already broke out above).
            let quota = total_continuing / (remaining_seats + 1) + 1;

            // Check for candidates reaching the quota.
            let newly_elected: Vec<u32> = active
                .iter()
                .copied()
                .filter(|&candidate| {
                    counts
                        .get(&candidate)
                        .copied()
                        .expect("active candidate counted")
                        >= quota
                })
                .collect();

            if !newly_elected.is_empty() {
                // Snapshot the active set before removing the newly-elected candidates: the
                // surplus transfer must check each ballot's top choice among the set that was
                // active when the round's counts were computed, not the post-removal set.
                let active_before: BTreeSet<u32> = active.iter().copied().collect();

                // Elect all candidates who reached the quota this round.
                for &candidate in &newly_elected {
                    elected.push(candidate);
                    active.remove(&candidate);
                }

                // Transfer surplus from each newly-elected candidate to those ballots' next
                // preferences. Only ballots whose top active choice was this candidate (per the
                // pre-removal set) are scaled by surplus / count (the transfer fraction);
                // ballots whose top preference is still-active candidates keep their weight.
                for &candidate in &newly_elected {
                    let candidate_count = counts
                        .get(&candidate)
                        .copied()
                        .expect("newly elected candidate counted");
                    if candidate_count == 0 {
                        continue;
                    }
                    let surplus = candidate_count - quota;

                    for ballot in &mut weighted_ballots {
                        // Each ballot is a full permutation, so `find` always lands on this
                        // ballot's highest-ranked candidate that was active this round.
                        let top_choice = ballot
                            .ranking
                            .iter()
                            .copied()
                            .find(|c| active_before.contains(c));
                        if top_choice == Some(candidate) {
                            // Scale this ballot's weight by surplus / count.
                            ballot.weight = ballot.weight * surplus / candidate_count;
                        }
                    }
                }

                rounds.push(Round {
                    counts,
                    elected: newly_elected,
                    eliminated: None,
                    quota,
                });
                continue;
            }

            // No candidate reached quota — eliminate the lowest-count candidate.
            // Ties broken by lowest candidate id (BTreeSet iteration order).
            let min_count = *counts.values().min().expect("non-empty active set");
            let to_eliminate = active
                .iter()
                .copied()
                .find(|candidate| {
                    counts
                        .get(candidate)
                        .copied()
                        .expect("active candidate counted")
                        == min_count
                })
                .expect("an elimination candidate exists when active set is non-empty");

            active.remove(&to_eliminate);

            // Eliminated candidate's ballots transfer at full weight to their next preference.
            // No weight change needed — the next count round will pick up the next preference
            // automatically since the eliminated candidate is no longer active.

            rounds.push(Round {
                counts,
                elected: Vec::new(),
                eliminated: Some(to_eliminate),
                quota,
            });
        }

        (elected, rounds)
    }
}

/// Pure sequential-IRV tally logic for multi-winner elections, isolated from the template engine
/// so it can be unit-tested directly.
///
/// Sequential IRV runs single-winner IRV to fill the first seat, removes the winner from all
/// ballots, then runs IRV again on the remaining candidates to fill the second seat, and so on
/// until all seats are filled. It is simpler than STV (no quotas, no surplus transfer, no
/// fractional weights) and reuses the existing `run_irv` function directly.
///
/// This is the **default multi-winner method** when `num_winners > 1`. STV remains available for
/// those who prefer proportional representation, but sequential IRV is simpler and easier to audit.
pub mod sequential_irv {
    use super::irv::{Round as IrvRound, run_irv};

    /// One seat's election: the winner (if any) and the IRV sub-rounds that elected them.
    pub struct Seat {
        /// The candidate who won this seat, or `None` if no winner could be determined.
        pub winner: Option<u32>,
        /// The per-round IRV tally trace for this seat's election.
        pub irv_rounds: Vec<IrvRound>,
    }

    /// Sequential-IRV tally over a set of ballots. Each ballot is a permutation of
    /// `0..num_candidates` ordered by preference (index 0 = first choice).
    ///
    /// For each seat: run `run_irv` on the current ballots (with previously-elected candidates
    /// removed and remaining candidates reindexed to 0..N), record the winner, map it back to
    /// the original candidate id, then remove the winner from all ballots for the next seat.
    /// Ties for elimination are broken by lowest candidate id (inherited from `run_irv`),
    /// so all validators agree on the outcome.
    ///
    /// Returns `(winners, seats)` where `winners` is the list of elected candidates in order and
    /// `seats` is the per-seat tally trace.
    pub fn run_sequential_irv(
        ballots: &[Vec<u32>],
        num_candidates: u32,
        num_winners: u32,
    ) -> (Vec<u32>, Vec<Seat>) {
        let mut winners: Vec<u32> = Vec::new();
        let mut seats: Vec<Seat> = Vec::new();

        let mut current_ballots: Vec<Vec<u32>> = ballots.to_vec();

        for _seat_index in 0..num_winners {
            // Candidates still in contention: everyone except those already elected.
            let remaining_candidates: Vec<u32> = (0..num_candidates)
                .filter(|candidate| !winners.contains(candidate))
                .collect();

            if remaining_candidates.is_empty() {
                seats.push(Seat {
                    winner: None,
                    irv_rounds: Vec::new(),
                });
                continue;
            }

            // Build a mapping from original candidate id → reindexed id (0..N) for run_irv.
            let original_to_reindexed: std::collections::BTreeMap<u32, u32> = remaining_candidates
                .iter()
                .enumerate()
                .map(|(reindexed, &original)| (original, reindexed as u32))
                .collect();
            let reindexed_to_original: std::collections::BTreeMap<u32, u32> = original_to_reindexed
                .iter()
                .map(|(&original, &reindexed)| (reindexed, original))
                .collect();

            // Reindex each ballot's candidates to the 0..N range, preserving preference order.
            let reindexed_ballots: Vec<Vec<u32>> = current_ballots
                .iter()
                .map(|ballot| {
                    ballot
                        .iter()
                        .copied()
                        .filter_map(|candidate| original_to_reindexed.get(&candidate).copied())
                        .collect()
                })
                .collect();

            let remaining_count = remaining_candidates.len() as u32;
            let (reindexed_winner, irv_rounds) = run_irv(&reindexed_ballots, remaining_count);

            if let Some(reindexed_winner_id) = reindexed_winner {
                let original_id = reindexed_to_original[&reindexed_winner_id];
                winners.push(original_id);

                // Remove the winner from current_ballots for the next seat.
                for ballot in &mut current_ballots {
                    ballot.retain(|candidate| *candidate != original_id);
                }

                seats.push(Seat {
                    winner: Some(original_id),
                    irv_rounds,
                });
            } else {
                seats.push(Seat {
                    winner: None,
                    irv_rounds,
                });
                break;
            }
        }

        (winners, seats)
    }
}

/// Pure first-past-the-post tally logic, isolated from the template engine so it can be
/// unit-tested directly without stealth-transfer machinery. Returns simple types (winner +
/// first-preference counts) with no dependency on template ABI traits; the template's
/// `result()` method wraps the output into the ABI-compatible `FptpResult` struct.
pub mod fptp {
    use super::unique_plurality_winner;
    use std::collections::BTreeMap;

    /// First-past-the-post tally over a set of ranked ballots. Each ballot is a permutation of
    /// `0..num_candidates` ordered by preference; only the first preference (`ranking[0]`)
    /// counts as a vote.
    ///
    /// The candidate with the most first-preference votes wins — no majority is required. A tie
    /// for the most votes has no winner: returns `None` (zero turnout is the degenerate tie —
    /// every count is 0 — and yields the same result). Ties and zero turnout are decided by the
    /// same `unique_plurality_winner` check; the winner must hold a strictly unique count.
    ///
    /// Returns `(winner, counts)` where `winner` is `Some(candidate_id)` or `None`, and `counts`
    /// maps every candidate to its first-preference count.
    pub fn run_fptp(
        ballots: &[Vec<u32>],
        num_candidates: u32,
    ) -> (Option<u32>, BTreeMap<u32, u64>) {
        let mut counts: BTreeMap<u32, u64> = (0..num_candidates).map(|c| (c, 0u64)).collect();
        for ballot in ballots {
            if let Some(&first) = ballot.first().filter(|first| counts.contains_key(first)) {
                *counts.get_mut(&first).expect("first preference counted") += 1;
            }
        }

        // Ties and zero turnout share one decision: the winner must be a strictly unique,
        // positive maximum. Zero turnout (all counts 0) is the degenerate tie and returns
        // `None` through this same check.
        let winner = unique_plurality_winner(&counts);
        (winner, counts)
    }
}
