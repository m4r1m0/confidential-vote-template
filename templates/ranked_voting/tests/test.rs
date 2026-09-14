use rcv_tally::TallyMethod;
use rcv_tally::irv::run_irv;
use tari_template_lib::prelude::Amount;
use tari_template_lib::types::SubstateOwnerRule;
use tari_template_lib::types::access_rules::{
    AccessRule, RequireRule, ResourceAuthAction, RestrictedAccessRule, RuleRequirement, UpdateRule,
};
use tari_template_lib::types::constants::TARI_TOKEN;
use tari_template_test_tooling::TemplateTest;
use tari_template_test_tooling::byte_type::ToByteType;
use tari_template_test_tooling::crypto::{PublicKey, RistrettoPublicKey, RistrettoSecretKey};
use tari_template_test_tooling::engine_types::virtual_substate::{
    VirtualSubstate, VirtualSubstateId,
};
use tari_template_test_tooling::support::assert_error::assert_reject_reason;
use tari_template_test_tooling::support::stealth::{
    StealthSecretTransferData, generate_transfer_data, test_sender_public_nonce,
};
use tari_template_test_tooling::template_lib_types::{
    EncryptedData, crypto::UtxoTag, stealth::SpendAuthorization,
};
use tari_template_test_tooling::transaction::{Epoch, Transaction, args};
use tari_template_test_tooling::wallet_crypto::stealth::create_transfer_statement;
use tari_template_test_tooling::wallet_crypto::{
    MaskAndValue, OutputWitness, StealthOutputWitness,
};

/// Helper: ballot `[a, b, c]` means a=1st choice, b=2nd, c=3rd.
fn ballot(rank: &[u32]) -> Vec<u32> {
    rank.to_vec()
}

// ───────────────────────── IRV unit tests ─────────────────────────

#[test]
fn test_majority_first_round() {
    let ballots = vec![
        ballot(&[0, 1, 2]),
        ballot(&[0, 1, 2]),
        ballot(&[0, 2, 1]),
        ballot(&[1, 0, 2]),
        ballot(&[2, 0, 1]),
    ];
    let (winner, rounds) = run_irv(&ballots, 3);
    assert_eq!(winner, Some(0));
    assert_eq!(rounds.len(), 1);
    assert_eq!(rounds[0].counts.get(&0), Some(&3));
    assert_eq!(rounds[0].counts.get(&1), Some(&1));
    assert_eq!(rounds[0].counts.get(&2), Some(&1));
    assert!(rounds[0].eliminated.is_none());
}

#[test]
fn test_tie_after_redistribution_yields_no_winner() {
    // Round 1: 0=2, 1=1, 2=1. No majority; 1 is eliminated (unique lowest).
    // Round 2: 0=2, 2=2. The final two are tied, so there is no winner.
    let ballots = vec![
        ballot(&[0, 2, 1]),
        ballot(&[0, 2, 1]),
        ballot(&[1, 2, 0]),
        ballot(&[2, 1, 0]),
    ];
    let (winner, rounds) = run_irv(&ballots, 3);
    assert_eq!(winner, None);
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[0].eliminated, Some(1));
    assert!(rounds[1].eliminated.is_none());
}

#[test]
fn test_final_round_tie_yields_no_winner() {
    // 1-1 between the final two candidates: a tied outcome, so no winner — the count must not
    // crown the elimination survivor.
    let ballots = vec![ballot(&[0, 1]), ballot(&[1, 0])];
    let (winner, rounds) = run_irv(&ballots, 2);
    assert_eq!(winner, None);
    assert_eq!(rounds.len(), 1);
    assert!(rounds[0].eliminated.is_none());
}

#[test]
fn test_single_candidate() {
    let ballots = vec![ballot(&[0]), ballot(&[0])];
    let (winner, rounds) = run_irv(&ballots, 1);
    assert_eq!(winner, Some(0));
    assert_eq!(rounds.len(), 1);
}

#[test]
fn test_single_voter() {
    let ballots = vec![ballot(&[2, 0, 1])];
    let (winner, rounds) = run_irv(&ballots, 3);
    assert_eq!(winner, Some(2));
    assert_eq!(rounds.len(), 1);
}

#[test]
fn test_elimination_ties_continue_until_final_round() {
    // Round 1: 1-1-1-1, all tied for lowest → lowest id (0) eliminated.
    // Round 2: 1=2, 2=1, 3=1 → 2 eliminated (lowest id among the tied 2, 3).
    // Round 3: 1=2, 3=2 — the final two are tied, so there is no winner.
    let ballots = vec![
        ballot(&[0, 1, 2, 3]),
        ballot(&[1, 2, 3, 0]),
        ballot(&[2, 3, 0, 1]),
        ballot(&[3, 0, 1, 2]),
    ];
    let (winner, rounds) = run_irv(&ballots, 4);
    assert_eq!(winner, None);
    assert_eq!(rounds.len(), 3);
    assert_eq!(rounds[0].eliminated, Some(0));
    assert_eq!(rounds[1].eliminated, Some(2));
    assert!(rounds[2].eliminated.is_none());
}

#[test]
fn test_no_ballots() {
    // Zero turnout: nobody voted, so there must be no winner — the elimination tie-breaks
    // must not crown an arbitrary candidate. This is the behavior `end_vote_expired` relies on
    // when an election expires with zero ballots cast.
    let (winner, rounds) = run_irv(&[], 3);
    assert_eq!(winner, None);
    assert_eq!(rounds.len(), 1);
    assert!(rounds[0].eliminated.is_none());
}

#[test]
fn test_redistribution_to_second_choice() {
    let ballots = vec![ballot(&[0, 2, 1]), ballot(&[1, 2, 0]), ballot(&[2, 0, 1])];
    let (winner, rounds) = run_irv(&ballots, 3);
    assert_eq!(winner, Some(2));
    assert_eq!(rounds[0].eliminated, Some(0));
    assert_eq!(rounds[1].counts.get(&2), Some(&2));
}

#[test]
fn test_fifty_fifty_final_round_is_no_winner() {
    // 2-2 between the final two candidates: exactly half is not a majority and the tie means
    // there is no winner.
    let ballots = vec![
        ballot(&[0, 1]),
        ballot(&[0, 1]),
        ballot(&[1, 0]),
        ballot(&[1, 0]),
    ];
    let (winner, rounds) = run_irv(&ballots, 2);
    assert_eq!(winner, None);
    assert_eq!(rounds.len(), 1);
    assert!(rounds[0].eliminated.is_none());
}

#[test]
fn test_determinism_same_result() {
    let ballots = vec![
        ballot(&[1, 0, 2]),
        ballot(&[2, 1, 0]),
        ballot(&[0, 2, 1]),
        ballot(&[1, 2, 0]),
        ballot(&[0, 1, 2]),
    ];
    let (w1, r1) = run_irv(&ballots, 3);
    let (w2, r2) = run_irv(&ballots, 3);
    assert_eq!(w1, w2);
    assert_eq!(r1.len(), r2.len());
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a.counts, b.counts);
        assert_eq!(a.eliminated, b.eliminated);
    }
}

// ───────────────────────── FPTP unit tests ─────────────────────────
// First past the post counts each ballot's first preference only; the most votes win with no
// majority required.

use rcv_tally::fptp::run_fptp;

#[test]
fn test_fptp_plurality_without_majority() {
    // 4 votes, 3 candidates: 2/1/1. No candidate has >50%, but FPTP crowns the plurality
    // leader (IRV would eliminate the lowest and keep going).
    let ballots = vec![
        ballot(&[0, 1, 2]),
        ballot(&[0, 1, 2]),
        ballot(&[1, 2, 0]),
        ballot(&[2, 1, 0]),
    ];
    let (winner, counts) = run_fptp(&ballots, 3);
    assert_eq!(winner, Some(0));
    assert_eq!(counts.get(&0), Some(&2));
    assert_eq!(counts.get(&1), Some(&1));
    assert_eq!(counts.get(&2), Some(&1));
}

#[test]
fn test_fptp_tie_yields_no_winner() {
    // 2 candidates, 1-1 tie: a tied outcome has no winner — the count must not crown the
    // lowest-id candidate.
    let ballots = vec![ballot(&[0, 1]), ballot(&[1, 0])];
    let (winner, counts) = run_fptp(&ballots, 2);
    assert_eq!(winner, None);
    assert_eq!(counts.get(&0), Some(&1));
    assert_eq!(counts.get(&1), Some(&1));
}

#[test]
fn test_fptp_three_way_tie_yields_no_winner() {
    // 1-1-1: the maximum count is shared by all three candidates, so there is no winner.
    let ballots = vec![ballot(&[0, 1, 2]), ballot(&[1, 2, 0]), ballot(&[2, 0, 1])];
    let (winner, counts) = run_fptp(&ballots, 3);
    assert_eq!(winner, None);
    assert_eq!(counts.get(&0), Some(&1));
    assert_eq!(counts.get(&1), Some(&1));
    assert_eq!(counts.get(&2), Some(&1));
}

#[test]
fn test_zero_turnout_and_tie_share_the_same_result() {
    // Zero turnout is the degenerate tie (every count is 0); a 1-1 tie is the same shape.
    // Both must produce no winner through the same unique-winner check.
    let (zero_winner, zero_counts) = run_fptp(&[], 2);
    let (tie_winner, tie_counts) = run_fptp(&[ballot(&[0, 1]), ballot(&[1, 0])], 2);
    assert_eq!(zero_winner, None);
    assert_eq!(tie_winner, None);
    assert_eq!(zero_counts.values().max(), Some(&0));
    assert_eq!(tie_counts.values().max(), Some(&1));
}

#[test]
fn test_unique_plurality_winner_helper() {
    use rcv_tally::unique_plurality_winner;
    use std::collections::BTreeMap;

    let mut unique = BTreeMap::new();
    unique.insert(0u32, 2u64);
    unique.insert(1, 1);
    assert_eq!(unique_plurality_winner(&unique), Some(0));

    let mut shared = BTreeMap::new();
    shared.insert(0u32, 1u64);
    shared.insert(1, 1);
    assert_eq!(unique_plurality_winner(&shared), None);

    let mut zero = BTreeMap::new();
    zero.insert(0u32, 0u64);
    zero.insert(1, 0);
    assert_eq!(unique_plurality_winner(&zero), None);

    let mut single = BTreeMap::new();
    single.insert(0u32, 3u64);
    assert_eq!(unique_plurality_winner(&single), Some(0));

    assert_eq!(unique_plurality_winner(&BTreeMap::new()), None);
}

#[test]
fn test_fptp_first_preference_only() {
    // A ballot's second and third preferences never count. Ballot [0, 1, 2] votes for 0 only,
    // regardless of how the rest of the field performs.
    let ballots = vec![
        ballot(&[0, 1, 2]),
        ballot(&[1, 0, 2]),
        ballot(&[1, 2, 0]),
        ballot(&[2, 1, 0]),
    ];
    let (winner, counts) = run_fptp(&ballots, 3);
    assert_eq!(winner, Some(1));
    assert_eq!(counts.get(&0), Some(&1));
    assert_eq!(counts.get(&1), Some(&2));
    assert_eq!(counts.get(&2), Some(&1));
}

#[test]
fn test_fptp_yes_no_two_candidates() {
    // Two candidates = plain yes/no vote. Candidate 0 ("yes") wins 3-2.
    let ballots = vec![
        ballot(&[0, 1]),
        ballot(&[0, 1]),
        ballot(&[0, 1]),
        ballot(&[1, 0]),
        ballot(&[1, 0]),
    ];
    let (winner, counts) = run_fptp(&ballots, 2);
    assert_eq!(winner, Some(0));
    assert_eq!(counts.get(&0), Some(&3));
    assert_eq!(counts.get(&1), Some(&2));
}

#[test]
fn test_fptp_no_ballots() {
    // Zero turnout: nobody voted, so there is no winner — the degenerate tie where every
    // count is 0, decided by the same unique-winner check as a shared-max tie.
    let (winner, counts) = run_fptp(&[], 3);
    assert_eq!(winner, None);
    assert_eq!(counts.get(&0), Some(&0));
    assert_eq!(counts.get(&1), Some(&0));
    assert_eq!(counts.get(&2), Some(&0));
}

#[test]
fn test_fptp_single_candidate() {
    // A sole candidate wins every ballot; degenerate but defined.
    let ballots = vec![ballot(&[0]), ballot(&[0])];
    let (winner, counts) = run_fptp(&ballots, 1);
    assert_eq!(winner, Some(0));
    assert_eq!(counts.get(&0), Some(&2));
}

#[test]
fn test_fptp_single_voter() {
    let ballots = vec![ballot(&[2, 0, 1])];
    let (winner, counts) = run_fptp(&ballots, 3);
    assert_eq!(winner, Some(2));
    assert_eq!(counts.get(&2), Some(&1));
}

#[test]
fn test_fptp_determinism() {
    let ballots = vec![
        ballot(&[1, 0, 2]),
        ballot(&[2, 1, 0]),
        ballot(&[0, 2, 1]),
        ballot(&[1, 2, 0]),
        ballot(&[0, 1, 2]),
    ];
    let (w1, c1) = run_fptp(&ballots, 3);
    let (w2, c2) = run_fptp(&ballots, 3);
    assert_eq!(w1, w2);
    assert_eq!(c1, c2);
}

// ───────────────────────── STV unit tests ─────────────────────────

mod stv_tests {
    use super::ballot;
    use rcv_tally::irv::run_irv;
    use rcv_tally::stv::run_stv;

    #[test]
    fn test_stv_transfer_only_top_active_ballots() {
        // 3 candidates, 2 winners. Round 1: 0 = 40_000 >= quota 16_667, elected with surplus
        // 23_333. The four [0,1,2] ballots (top active choice 0) are scaled to 5833, but the
        // [2,1,0] ballot's top active choice (2) is still active, so it must keep full weight.
        // Round 2 (per the pre-removal active set): 1 = 4 * 5833 = 23_332, 2 = 10_000.
        let ballots = vec![
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[2, 1, 0]),
        ];
        let (winners, rounds) = run_stv(&ballots, 3, 2);
        assert_eq!(winners, vec![0, 1]);
        assert_eq!(rounds[0].elected, vec![0]);
        // Round 2: the [2,1,0] ballot still carries its full weight to candidate 2, proving
        // the surplus transfer did not touch it (the buggy transfer scales it to 5833).
        assert_eq!(rounds[1].counts.get(&1), Some(&23_332));
        assert_eq!(rounds[1].counts.get(&2), Some(&10_000));
    }

    #[test]
    fn test_stv_surplus_transfer_does_not_shift_winners() {
        // Regression: scaling ballots that never ranked the elected candidate as top active
        // choice can change the elected set. 4 candidates, 2 winners:
        //   Round 1: 2 = 30_000 >= quota 23_334, elected; surplus 6_666 scales the three
        //     [2,1,3,0] ballots to 2222 each, others keep 10_000.
        //   Round 2: 0 = 20_000, 1 = 16_666, 3 = 10_000 — no quota (23_334); 3 eliminated.
        //   Round 3: 0 = 30_000 >= quota; elected. Winners: [2, 0].
        // The buggy transfer (every ballot scaled every time) instead elects 1 in round 2
        // and returns [2, 1].
        let ballots = vec![
            ballot(&[2, 1, 3, 0]),
            ballot(&[2, 1, 3, 0]),
            ballot(&[2, 1, 3, 0]),
            ballot(&[0, 2, 3, 1]),
            ballot(&[0, 1, 2, 3]),
            ballot(&[3, 0, 1, 2]),
            ballot(&[1, 2, 3, 0]),
        ];
        let (winners, rounds) = run_stv(&ballots, 4, 2);
        assert_eq!(winners, vec![2, 0]);
        assert_eq!(rounds[0].elected, vec![2]);
        assert_eq!(rounds[1].eliminated, Some(3));
        assert_eq!(rounds[2].elected, vec![0]);
    }

    #[test]
    fn test_stv_two_winners_three_candidates() {
        let ballots = vec![
            ballot(&[0, 1, 2, 3]),
            ballot(&[0, 1, 2, 3]),
            ballot(&[0, 1, 2, 3]),
            ballot(&[1, 0, 2, 3]),
            ballot(&[2, 3, 0, 1]),
            ballot(&[3, 2, 0, 1]),
        ];
        let (winners, _rounds) = run_stv(&ballots, 4, 2);
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&0));
    }

    #[test]
    fn test_stv_surplus_transfer() {
        let ballots = vec![
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[2, 1, 0]),
        ];
        let (winners, _rounds) = run_stv(&ballots, 3, 2);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0], 0);
        assert_eq!(winners[1], 1);
    }

    #[test]
    fn test_stv_all_seats_filled_by_elimination() {
        let ballots = vec![
            ballot(&[0, 1, 2, 3]),
            ballot(&[1, 2, 3, 0]),
            ballot(&[2, 3, 0, 1]),
            ballot(&[3, 0, 1, 2]),
        ];
        let (winners, _rounds) = run_stv(&ballots, 4, 2);
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&1));
        assert!(winners.contains(&2));
    }

    #[test]
    fn test_stv_quota_calculation() {
        let ballots = vec![
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[1, 0, 2]),
            ballot(&[1, 0, 2]),
            ballot(&[1, 0, 2]),
        ];
        let (winners, rounds) = run_stv(&ballots, 3, 2);
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&0));
        assert!(winners.contains(&1));
        // 6 ballots * 10000 scale = 60000 total. Droop = floor(60000/3) + 1 = 20001
        assert_eq!(rounds[0].quota, 20_001);
    }

    #[test]
    fn test_stv_single_winner_matches_irv_behavior() {
        let ballots = vec![
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[1, 0, 2]),
            ballot(&[2, 0, 1]),
        ];
        let (irv_winner, _) = run_irv(&ballots, 3);
        let (stv_winners, _) = run_stv(&ballots, 3, 1);
        assert_eq!(stv_winners.len(), 1);
        assert_eq!(Some(stv_winners[0]), irv_winner);
    }

    #[test]
    fn test_stv_fewer_candidates_than_seats() {
        let ballots = vec![ballot(&[0, 1]), ballot(&[1, 0])];
        let (winners, _rounds) = run_stv(&ballots, 2, 3);
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&0));
        assert!(winners.contains(&1));
    }

    #[test]
    fn test_stv_determinism() {
        let ballots = vec![
            ballot(&[1, 0, 2, 3]),
            ballot(&[2, 1, 0, 3]),
            ballot(&[0, 2, 1, 3]),
            ballot(&[3, 0, 1, 2]),
            ballot(&[1, 2, 3, 0]),
        ];
        let (winners1, rounds1) = run_stv(&ballots, 4, 2);
        let (winners2, rounds2) = run_stv(&ballots, 4, 2);
        assert_eq!(winners1, winners2);
        assert_eq!(rounds1.len(), rounds2.len());
    }

    #[test]
    fn test_stv_no_ballots() {
        // Zero turnout: nobody voted, so nobody is elected. (Without the zero-turnout guard,
        // the Droop quota computes to 0 and every candidate would satisfy `count >= quota`.)
        let (winners, rounds) = run_stv(&[], 3, 2);
        assert!(winners.is_empty());
        assert!(rounds.is_empty());
    }
}

// ─────────────────── Sequential IRV unit tests ───────────────────

mod sequential_irv_tests {
    use super::ballot;
    use rcv_tally::irv::run_irv;
    use rcv_tally::sequential_irv::run_sequential_irv;

    #[test]
    fn test_sequential_irv_two_winners() {
        // 4 candidates, 2 seats, 5 voters.
        //   Voters 1-3: [0, 1, 2, 3]
        //   Voter 4: [1, 0, 2, 3]
        //   Voter 5: [2, 0, 1, 3]
        // Seat 1: IRV on all 4 candidates. 0 gets 3/5 = 60% > 50% → winner = 0.
        // Seat 2: Remove 0 from ballots. Ballots become [1,2,3], [1,2,3], [1,2,3], [1,2,3], [2,1,3].
        //   Reindexed: candidates 1,2,3 → 0,1,2. Ballots: [0,1,2]*4, [1,0,2].
        //   IRV: 0 gets 4/5 = 80% > 50% → winner = reindexed 0 = original 1.
        // Winners: [0, 1]
        let ballots = vec![
            ballot(&[0, 1, 2, 3]),
            ballot(&[0, 1, 2, 3]),
            ballot(&[0, 1, 2, 3]),
            ballot(&[1, 0, 2, 3]),
            ballot(&[2, 0, 1, 3]),
        ];
        let (winners, seats) = run_sequential_irv(&ballots, 4, 2);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0], 0);
        assert_eq!(winners[1], 1);
        assert_eq!(seats.len(), 2);
        // First seat should have IRV sub-rounds (decided in round 1)
        assert_eq!(seats[0].winner, Some(0));
        assert!(!seats[0].irv_rounds.is_empty());
    }

    #[test]
    fn test_sequential_irv_winner_removed_from_ballots() {
        // Verify that the winner of seat 1 is not available for seat 2.
        // 3 candidates, 2 seats, 3 voters.
        //   Voter 1: [0, 1, 2]
        //   Voter 2: [0, 2, 1]
        //   Voter 3: [1, 0, 2]
        // Seat 1: 0 gets 2/3 = 67% > 50% → winner = 0.
        // Seat 2: Remove 0. Ballots: [1,2], [2,1], [1,2].
        //   Reindexed: 1,2 → 0,1. Ballots: [0,1], [1,0], [0,1].
        //   IRV: 0 gets 2/3 = 67% → winner = reindexed 0 = original 1.
        // Winners: [0, 1]. Candidate 0 does NOT appear again.
        let ballots = vec![ballot(&[0, 1, 2]), ballot(&[0, 2, 1]), ballot(&[1, 0, 2])];
        let (winners, _) = run_sequential_irv(&ballots, 3, 2);
        assert_eq!(winners, vec![0, 1]);
        // 0 should appear exactly once
        assert_eq!(winners.iter().filter(|&&w| w == 0).count(), 1);
    }

    #[test]
    fn test_sequential_irv_more_seats_than_candidates() {
        // 2 candidates, 3 seats. Only 2 can be elected.
        //   Voter 1: [0, 1]
        //   Voter 2: [0, 1]
        //   Voter 3: [1, 0]
        // Seat 1: 0 gets 2/3 = 67% → winner = 0.
        // Seat 2: Remove 0. Ballots: [1], [1], [1]. Only candidate 1 remains → winner = 1.
        // Seat 3: No candidates remain → winner = None.
        let ballots = vec![ballot(&[0, 1]), ballot(&[0, 1]), ballot(&[1, 0])];
        let (winners, seats) = run_sequential_irv(&ballots, 2, 3);
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&0));
        assert!(winners.contains(&1));
        // Third seat should have no winner
        assert_eq!(seats[2].winner, None);
    }

    #[test]
    fn test_sequential_irv_single_winner_matches_irv() {
        // With 1 winner, sequential IRV should produce the same result as plain IRV.
        let ballots = vec![
            ballot(&[0, 1, 2]),
            ballot(&[0, 1, 2]),
            ballot(&[1, 0, 2]),
            ballot(&[2, 0, 1]),
        ];
        let (irv_winner, _) = run_irv(&ballots, 3);
        let (seq_winners, _) = run_sequential_irv(&ballots, 3, 1);
        assert_eq!(seq_winners.len(), 1);
        assert_eq!(Some(seq_winners[0]), irv_winner);
    }

    #[test]
    fn test_sequential_irv_tied_seat_yields_no_winner_and_stops() {
        // 2 candidates, 2 seats, 2-2 split: the first seat's election is a final-round tie,
        // so that seat has no winner and no further seats are filled — the unfilled-seat
        // (by-election) outcome.
        let ballots = vec![
            ballot(&[0, 1]),
            ballot(&[0, 1]),
            ballot(&[1, 0]),
            ballot(&[1, 0]),
        ];
        let (winners, seats) = run_sequential_irv(&ballots, 2, 2);
        assert_eq!(winners.len(), 0);
        assert_eq!(seats.len(), 1);
        assert_eq!(seats[0].winner, None);
    }

    #[test]
    fn test_sequential_irv_determinism() {
        let ballots = vec![
            ballot(&[1, 0, 2, 3]),
            ballot(&[2, 1, 0, 3]),
            ballot(&[0, 2, 1, 3]),
            ballot(&[3, 0, 1, 2]),
            ballot(&[1, 2, 3, 0]),
        ];
        let (winners1, seats1) = run_sequential_irv(&ballots, 4, 2);
        let (winners2, seats2) = run_sequential_irv(&ballots, 4, 2);
        assert_eq!(winners1, winners2);
        assert_eq!(seats1.len(), seats2.len());
        for (seat_a, seat_b) in seats1.iter().zip(seats2.iter()) {
            assert_eq!(seat_a.winner, seat_b.winner);
            assert_eq!(seat_a.irv_rounds.len(), seat_b.irv_rounds.len());
        }
    }

    #[test]
    fn test_sequential_irv_no_ballots() {
        // Zero turnout: seat 1's IRV returns no winner, so the sequential tally stops with no
        // winners elected.
        let (winners, seats) = run_sequential_irv(&[], 3, 2);
        assert!(winners.is_empty());
        assert_eq!(seats.len(), 1);
        assert!(seats[0].winner.is_none());
    }

    #[test]
    fn test_sequential_irv_redistribution_between_seats() {
        // Verify that elimination rounds in seat 1 redistribute votes that affect seat 2.
        // 4 candidates, 2 seats, 6 voters.
        //   Voters 1-2: [0, 3, 1, 2]
        //   Voters 3-4: [1, 3, 0, 2]
        //   Voter 5: [2, 3, 0, 1]
        //   Voter 6: [3, 0, 1, 2]
        // Seat 1: 0=2, 1=2, 2=1, 3=1. No majority. Eliminate 2 (lowest count among tied 2,3 → 2 is lower id).
        //   Voter 5's ballot redistributes to 3. Now 0=2, 1=2, 3=2. No majority.
        //   Eliminate 0 (lowest id among tied). Voters 1-2 redistribute to 3. Now 1=2, 3=4.
        //   3 has 4/6 = 67% > 50% → winner = 3.
        // Seat 2: Remove 3 from all ballots. Ballots: [0,1,2], [0,1,2], [1,0,2], [1,0,2], [2,0,1], [0,1,2].
        //   Reindexed: 0,1,2 → 0,1,2. 0=3, 1=2, 2=1. 3/6 = 50%, not > 50%.
        //   Eliminate 2 (lowest). Voter 5 redistributes to 0. 0=4, 1=2. 4/6 = 67% → winner = 0.
        // Winners: [3, 0]
        let ballots = vec![
            ballot(&[0, 3, 1, 2]),
            ballot(&[0, 3, 1, 2]),
            ballot(&[1, 3, 0, 2]),
            ballot(&[1, 3, 0, 2]),
            ballot(&[2, 3, 0, 1]),
            ballot(&[3, 0, 1, 2]),
        ];
        let (winners, seats) = run_sequential_irv(&ballots, 4, 2);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0], 3);
        assert_eq!(winners[1], 0);
        // Seat 1 should have multiple IRV rounds (redistribution happened)
        assert!(seats[0].irv_rounds.len() > 1);
    }
}

// ───────────────────── Adversarial in-process tests ─────────────────────
//
// These test the template's assertion guards directly using tari_template_test_tooling
// (in-process, no testnet needed). They cover the adversarial cases from review feedback:
// wrong token type while the vote is active, expired election, vote closed after
// finalization, mint statements with an output-count mismatch, wrong-valued ballot shapes
// (e.g. [2,0] — now rejected at construction by the per-output minimum-value-promise
// assert), nonsense parameters, and invalid rankings (wrong length / out-of-range candidate /
// duplicate candidate).
//
// Each test creates the component with the vote parameters in one `call_function("new", ...)`
// call. Tests that check invalid parameters assert on the constructor itself; tests that need a
// valid component use `create_vote` with valid params then exercise the post-creation methods.

/// Builds the mint statement for `voter_count` amount-1 ballot UTXOs, each promising a minimum
/// value of 1 (the invariant `new` enforces). The returned data keeps each UTXO's mask so tests
/// can spend the UTXOs later (each ballot UTXO is a key-path output whose spend key is its mask).
fn mint_ballots(voter_count: u64) -> StealthSecretTransferData {
    let outputs: Vec<(u64, u64)> = (0..voter_count).map(|_| (1, 1)).collect();
    mint_ballots_with_outputs(outputs)
}

/// Like `mint_ballots`, but with the given per-output amounts (each with a value-1 minimum
/// promise). The returned data keeps each UTXO's mask so tests can spend the UTXOs later.
fn mint_ballots_with_amounts(output_amounts: Vec<u64>) -> StealthSecretTransferData {
    mint_ballots_with_outputs(output_amounts.iter().map(|&amount| (amount, 1)).collect())
}

/// Builds a mint statement with the given `(amount, minimum_value_promise)` pairs for the output
/// set, mirroring the tooling's `generate_mint_statement` but with explicit per-output promises
/// (the tooling hardcodes promise 0). The returned data keeps each UTXO's mask so tests can spend
/// the UTXOs later.
fn mint_ballots_with_outputs(outputs: Vec<(u64, u64)>) -> StealthSecretTransferData {
    let masks: Vec<RistrettoSecretKey> = (0..outputs.len())
        .map(|i| RistrettoSecretKey::from(i as u64 + 1))
        .collect();
    let output_statements: Vec<StealthOutputWitness> = outputs
        .iter()
        .zip(&masks)
        .map(|((amount, promise), mask)| StealthOutputWitness {
            witness: OutputWitness {
                amount: *amount,
                mask: mask.clone(),
                sender_public_nonce: test_sender_public_nonce(),
                minimum_value_promise: *promise,
                encrypted_data: EncryptedData::try_from(vec![0; EncryptedData::min_size()])
                    .expect("valid encrypted data"),
                resource_view_key: None,
            },
            auth: SpendAuthorization::Key(RistrettoPublicKey::from_secret_key(mask).to_byte_type()),
            tag: UtxoTag::new(0),
        })
        .collect();

    let total: u64 = outputs.iter().map(|(amount, _)| amount).sum();
    let statement = create_transfer_statement(
        std::iter::empty(),
        Amount::from(total),
        output_statements.iter(),
        Amount::zero(),
    )
    .expect("valid transfer statement");

    StealthSecretTransferData {
        output_masks: masks,
        output_auths: vec![],
        statement,
    }
}

/// Creates a RankedVote component with the given parameters and returns
/// (component_address, ballot_resource_address, test, account, proof, secret).
fn create_vote(
    voter_count: u64,
    num_candidates: u32,
    num_winners: u32,
    tally_method: TallyMethod,
    expires_at_epoch: u64,
) -> (
    tari_template_lib::types::ComponentAddress,
    tari_template_lib::types::ResourceAddress,
    TemplateTest,
    tari_template_lib::types::ComponentAddress,
    tari_template_lib::types::NonFungibleAddress,
    tari_template_test_tooling::crypto::RistrettoSecretKey,
) {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("RankedVote");
    let (account, proof, secret) = test.create_funded_account();

    let mint_data = mint_ballots(voter_count);

    let transaction = test
        .transaction()
        .allocate_resource_address("ballot_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("ballot_res"),
                voter_count,
                num_candidates,
                num_winners,
                tally_method,
                expires_at_epoch,
                mint_data.statement,
            ],
        )
        .build_and_seal(&secret);

    let result = test.execute_expect_success(transaction, vec![proof.clone()]);
    let component_address = result
        .finalize
        .result
        .accept()
        .unwrap()
        .up_iter()
        .find_map(|(id, _)| id.as_component_address())
        .expect("component address");
    // Two resources are created by `new` (the ballot resource and the sealed mint badge), so
    // the ballot resource is identified semantically: it is the stealth resource that is not
    // TARI (the test tooling's TARI token is itself a stealth resource).
    let ballot_resource = test
        .read_only_state_store()
        .get_all_resources()
        .expect("resources")
        .into_iter()
        .find(|(address, resource)| resource.resource_type().is_stealth() && *address != TARI_TOKEN)
        .map(|(address, _)| address)
        .expect("ballot resource");

    (
        component_address,
        ballot_resource,
        test,
        account,
        proof,
        secret,
    )
}

/// Attempts to create a vote with the given parameters, expecting failure. Returns the
/// reject reason for assertion.
fn create_vote_expect_failure(
    voter_count: u64,
    num_candidates: u32,
    num_winners: u32,
    tally_method: TallyMethod,
    expires_at_epoch: u64,
) -> tari_template_test_tooling::engine_types::commit_result::RejectReason {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("RankedVote");
    let (_account, _proof, secret) = test.create_funded_account();

    let mint_data = mint_ballots(voter_count);

    let transaction = test
        .transaction()
        .allocate_resource_address("ballot_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("ballot_res"),
                voter_count,
                num_candidates,
                num_winners,
                tally_method,
                expires_at_epoch,
                mint_data.statement,
            ],
        )
        .build_and_seal(&secret);

    test.execute_expect_failure(transaction, vec![])
}

#[test]
fn rejects_zero_voter_count() {
    let reason = create_vote_expect_failure(0, 3, 1, TallyMethod::SequentialIrv, 1000);
    assert_reject_reason(reason, "voter_count must be positive");
}

#[test]
fn rejects_zero_candidates() {
    let reason = create_vote_expect_failure(1, 0, 1, TallyMethod::SequentialIrv, 1000);
    assert_reject_reason(reason, "num_candidates must be positive");
}

#[test]
fn rejects_more_winners_than_candidates() {
    let reason = create_vote_expect_failure(1, 2, 3, TallyMethod::SequentialIrv, 1000);
    assert_reject_reason(reason, "num_winners cannot exceed num_candidates");
}

#[test]
fn rejects_ballot_after_vote_closed() {
    let (component, _ballot_resource, mut test, account, proof, secret) =
        create_vote(1, 2, 1, TallyMethod::SequentialIrv, 1000);

    // End the vote.
    let end_transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&secret);
    test.execute_expect_success(end_transaction, vec![]);

    // Attempt to cast a ballot after the vote is closed. The `assert!(self.active)` fires
    // before the resource check, so we can use any withdrawable token here.
    let transaction = test
        .transaction()
        .call_method(account, "withdraw", args![TARI_TOKEN, Amount::from(1u64)])
        .put_last_instruction_output_on_workspace("bucket")
        .call_method(
            component,
            "cast_ballot",
            args![Workspace("bucket"), vec![0u32, 1u32]],
        )
        .build_and_seal(&secret);

    let reason = test.execute_expect_failure(transaction, vec![proof]);
    assert_reject_reason(reason, "No active vote");
}

#[test]
fn rejects_ballot_after_expiration() {
    let (component, _ballot_resource, mut test, account, proof, secret) =
        create_vote(1, 2, 1, TallyMethod::SequentialIrv, 10);

    // Advance the epoch past the expiration.
    test.set_virtual_substate(
        VirtualSubstateId::CurrentEpoch,
        VirtualSubstate::CurrentEpoch(11),
    );

    // Attempt to cast a ballot. The active check passes, but the expiration check fires.
    // We use TARI here — the expiration assertion fires before the resource check.
    let transaction = test
        .transaction()
        .call_method(account, "withdraw", args![TARI_TOKEN, Amount::from(1u64)])
        .put_last_instruction_output_on_workspace("bucket")
        .call_method(
            component,
            "cast_ballot",
            args![Workspace("bucket"), vec![0u32, 1u32]],
        )
        .build_and_seal(&secret);

    let reason = test.execute_expect_failure(transaction, vec![proof]);
    assert_reject_reason(reason, "Voting period has expired");
}

#[test]
fn rejects_wrong_token_while_vote_active() {
    let (component, _ballot_resource, mut test, account, proof, secret) =
        create_vote(1, 2, 1, TallyMethod::SequentialIrv, 1000);

    // The vote is live and unexpired, so the active and expiration checks pass and the
    // resource check fires: the bucket must hold the ballot token, not TARI.
    let transaction = test
        .transaction()
        .call_method(account, "withdraw", args![TARI_TOKEN, Amount::from(1u64)])
        .put_last_instruction_output_on_workspace("bucket")
        .call_method(
            component,
            "cast_ballot",
            args![Workspace("bucket"), vec![0u32, 1u32]],
        )
        .build_and_seal(&secret);

    let reason = test.execute_expect_failure(transaction, vec![proof]);
    assert_reject_reason(reason, "bucket must be the ballot resource");
}

#[test]
fn rejects_invalid_ranking() {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("RankedVote");
    let (_account, _proof, secret) = test.create_funded_account();

    // Create the vote manually (rather than via `create_vote`) so the ballot mint
    // statement — and therefore each UTXO's mask — is available for the spend below.
    let ballot_mint = mint_ballots(1);
    let transaction = test
        .transaction()
        .allocate_resource_address("ballot_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("ballot_res"),
                1u64,
                2u32,
                1u32,
                TallyMethod::SequentialIrv,
                1000u64,
                ballot_mint.statement,
            ],
        )
        .build_and_seal(&secret);
    let result = test.execute_expect_success(transaction, vec![]);
    let component = result
        .finalize
        .result
        .accept()
        .unwrap()
        .up_iter()
        .find_map(|(id, _)| id.as_component_address())
        .expect("component address");
    let ballot_resource = test
        .read_only_state_store()
        .get_all_resources()
        .expect("resources")
        .into_iter()
        .find(|(address, resource)| resource.resource_type().is_stealth() && *address != TARI_TOKEN)
        .map(|(address, _)| address)
        .expect("ballot resource");

    // Spend the ballot UTXO into `cast_ballot` with an invalid ranking. Failed
    // transactions roll back, so the same UTXO/mask is re-used for every attempt:
    // ranking with an out-of-range candidate id, duplicate candidate, wrong length.
    for (ranking, reason) in [
        (vec![2u32, 0u32], "candidate id 2 out of range"),
        (vec![0u32, 0u32], "candidate 0 ranked twice"),
        (vec![0u32], "ranking must list every candidate exactly once"),
    ] {
        let ballot_spend = generate_transfer_data(
            [MaskAndValue {
                mask: ballot_mint.output_masks[0].clone(),
                value: 1,
            }],
            0u64,
            Vec::<u64>::new(),
            1u64,
        );
        let transaction = Transaction::builder_localnet(Epoch(100))
            .stealth_transfer(ballot_resource, ballot_spend.statement)
            .put_last_instruction_output_on_workspace("vote")
            .call_method(component, "cast_ballot", args![Workspace("vote"), ranking])
            .finish()
            .add_signer(&test.to_public_key_bytes(), &ballot_mint.output_masks[0])
            .seal(test.secret_key());
        let reject = test.execute_expect_failure(transaction, vec![]);
        assert_reject_reason(reject, reason);
    }
}

#[test]
fn rejects_output_count_mismatch() {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("RankedVote");
    let (_account, _proof, secret) = test.create_funded_account();

    for (amounts, voter_count) in [(vec![2u64], 2u64), (vec![1u64, 2u64], 3u64)] {
        // Both statements have the right TOTAL (so the total assert passes) but create too few
        // outputs for the voters: [2] merges two ballots into one 2-token ballot; [1,2] leaves
        // the third voter without a ballot. The output-count assert fires at construction.
        let ballot_mint = mint_ballots_with_amounts(amounts);
        let transaction = test
            .transaction()
            .allocate_resource_address("ballot_res")
            .call_function(
                template_address,
                "new",
                args![
                    Workspace("ballot_res"),
                    voter_count,
                    2u32,
                    1u32,
                    TallyMethod::SequentialIrv,
                    1000u64,
                    ballot_mint.statement,
                ],
            )
            .build_and_seal(&secret);
        let reject = test.execute_expect_failure(transaction, vec![]);
        assert_reject_reason(
            reject,
            "mint statement must create one stealth output per voter",
        );
    }
}

#[test]
fn rejects_zero_value_ballot_shapes_at_construction() {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("RankedVote");
    let (_account, _proof, secret) = test.create_funded_account();

    // [2,0] with voter_count 2 has the right TOTAL (2) and the right OUTPUT COUNT (2), so it
    // passes the total and count asserts. A value-0 output can only ever be proven with a
    // minimum-value promise of 0 (any higher promise breaks the engine's range proof), so the
    // per-output promise assert in `new` fires at construction. The old cast-time amount guard
    // is therefore unreachable for wrong-valued ballots: no such ballot can exist.
    let bad_mint = mint_ballots_with_outputs(vec![(2u64, 1u64), (0u64, 0u64)]);
    let transaction = test
        .transaction()
        .allocate_resource_address("ballot_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("ballot_res"),
                2u64,
                2u32,
                1u32,
                TallyMethod::SequentialIrv,
                1000u64,
                bad_mint.statement,
            ],
        )
        .build_and_seal(&secret);
    let reject = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(
        reject,
        "each ballot output must promise a minimum value of 1",
    );

    // A [3,0,0] shape with voter_count 3 is rejected by the same assert: only the 3-token output
    // can promise its value, both 0-value outputs must promise 0.
    let bad_mint = mint_ballots_with_outputs(vec![(3u64, 1u64), (0u64, 0u64), (0u64, 0u64)]);
    let transaction = test
        .transaction()
        .allocate_resource_address("ballot_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("ballot_res"),
                3u64,
                2u32,
                1u32,
                TallyMethod::SequentialIrv,
                1000u64,
                bad_mint.statement,
            ],
        )
        .build_and_seal(&secret);
    let reject = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(
        reject,
        "each ballot output must promise a minimum value of 1",
    );
}

#[test]
fn rejects_end_vote_expired_before_deadline() {
    let (component, _ballot_resource, mut test, _account, _proof, secret) =
        create_vote(1, 2, 1, TallyMethod::SequentialIrv, 100);

    // Epoch is still 0 (default), well before expiration at 100.
    let transaction = test
        .transaction()
        .call_method(component, "end_vote_expired", args![])
        .build_and_seal(&secret);

    let reason = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(reason, "Voting period has not yet expired");
}

#[test]
fn anyone_can_finalize_expired_vote() {
    let (component, _ballot_resource, mut test, _account, _proof, _secret) =
        create_vote(1, 2, 1, TallyMethod::SequentialIrv, 0);

    // Advance the epoch past the expiration, so the vote is finalizable.
    test.set_virtual_substate(
        VirtualSubstateId::CurrentEpoch,
        VirtualSubstate::CurrentEpoch(1),
    );

    // A fresh account (not the initiator) can finalize the expired vote — `end_vote_expired` is
    // open to anyone, and the method's own assert verifies the deadline has passed.
    let (_other_account, _other_proof, other_secret) = test.create_funded_account();
    let transaction = test
        .transaction()
        .call_method(component, "end_vote_expired", args![])
        .build_and_seal(&other_secret);
    test.execute_expect_success(transaction, vec![]);
}

#[test]
fn ballot_minting_is_permanently_revoked() {
    let (component, ballot_resource, test, _account, _proof, _secret) =
        create_vote(3, 2, 1, TallyMethod::SequentialIrv, 1000);

    // The one-of mint badge is sealed inside the component; it is the component vault that does
    // not hold ballot tokens.
    let store = test.read_only_state_store();
    let vaults = store
        .get_vaults_for_component(component)
        .expect("component vaults");
    let badge_resource = vaults
        .values()
        .map(|vault| *vault.resource_address())
        .find(|address| *address != ballot_resource)
        .expect("badge vault");

    let ballot_def = store
        .get_resource(&ballot_resource)
        .expect("ballot resource");
    let badge_def = store.get_resource(&badge_resource).expect("badge resource");

    // Minting ballot tokens requires a proof of the sealed badge, and the rule is locked so it
    // can never be changed.
    let ballot_rules = ballot_def.access_rules();
    assert!(matches!(
        ballot_rules.get_updater(&ResourceAuthAction::Mint),
        UpdateRule::Locked,
    ));
    match ballot_rules.get_access_rule(&ResourceAuthAction::Mint) {
        AccessRule::Restricted(RestrictedAccessRule::Require(RequireRule::Require(
            RuleRequirement::Resource(address),
        ))) => assert_eq!(address, &badge_resource),
        other => panic!("unexpected ballot mint rule: {other:?}"),
    }
    // The ballot resource is ownerless, so the resource-owner authorization path (which would
    // bypass the mint rule) is closed. Burning ballots is denied outright (no one — including
    // the initiator — can ever burn ballot tokens); the withdraw rule stays allow_all because
    // the constructor's mint-to-stealth conversion is authorized by it, but no template method
    // ever exposes a ballot vault to callers, so it is inert.
    assert_eq!(ballot_def.owner_rule(), &SubstateOwnerRule::None);
    assert_eq!(
        ballot_rules.get_access_rule(&ResourceAuthAction::Burn),
        &AccessRule::DenyAll,
    );
    assert!(matches!(
        ballot_rules.get_updater(&ResourceAuthAction::Burn),
        UpdateRule::Locked,
    ));

    // The badge itself can never be minted, burned, recalled, or modified, so the one badge that
    // exists at construction is the only one that will ever exist. Its withdraw rule stays
    // allow_all (creating the constructor's mint proof is authorized by it) but is inert: vaults
    // cannot be addressed by transactions, and no template method exposes the sealed badge vault.
    let badge_rules = badge_def.access_rules();
    for action in [
        ResourceAuthAction::Mint,
        ResourceAuthAction::Burn,
        ResourceAuthAction::Recall,
        ResourceAuthAction::UpdateNonFungibleData,
    ] {
        assert_eq!(badge_rules.get_access_rule(&action), &AccessRule::DenyAll);
        assert!(matches!(
            badge_rules.get_updater(&action),
            UpdateRule::Locked
        ));
    }
    assert_eq!(
        badge_rules.get_access_rule(&ResourceAuthAction::Withdraw),
        &AccessRule::AllowAll
    );
    assert!(matches!(
        badge_rules.get_updater(&ResourceAuthAction::Withdraw),
        UpdateRule::Locked
    ));
    assert_eq!(badge_def.total_supply(), Some(Amount::from(1u64)));

    // Exactly one ballot per eligible voter was minted at construction, and the stored
    // voter_count matches (field index 8 = the 9th field of `RankedVote`, in declaration order,
    // after `tally_method`).
    assert_eq!(ballot_def.total_supply(), Some(Amount::from(3u64)));
    let voter_count: u64 = test.extract_component_value(component, "8");
    assert_eq!(voter_count, 3);
}

// ───────────────────── End-to-end stealth-ballot election ─────────────────────
//
// Mirrors the testnet scenario in `client/integration/src/main.rs` entirely in-process
// (no testnet needed): the vote is created, each voter spends their stealth ballot UTXO
// into `cast_ballot`, and `end_vote` produces the expected IRV winner. A single-winner election
// always takes the IRV path regardless of the pinned multi-winner method.

#[test]
fn end_to_end_three_voter_election() {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("RankedVote");
    let (_account, proof, secret) = test.create_funded_account();

    // Same scenario as the integration client: 3 voters, 3 candidates, 1 winner.
    let rankings: [[u32; 3]; 3] = [[0, 2, 1], [1, 2, 0], [2, 0, 1]];

    // Create the vote; the constructor mints one amount-1 ballot UTXO per voter.
    let ballot_mint = mint_ballots(3);
    let transaction = test
        .transaction()
        .allocate_resource_address("ballot_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("ballot_res"),
                3u64,
                3u32,
                1u32,
                TallyMethod::SequentialIrv,
                1000u64,
                ballot_mint.statement,
            ],
        )
        .build_and_seal(&secret);
    let result = test.execute_expect_success(transaction, vec![proof.clone()]);
    let component = result
        .finalize
        .result
        .accept()
        .unwrap()
        .up_iter()
        .find_map(|(id, _)| id.as_component_address())
        .expect("component address");
    // The ballot resource is the stealth resource that is not the test tooling's TARI token.
    let ballot_resource = test
        .read_only_state_store()
        .get_all_resources()
        .expect("resources")
        .into_iter()
        .find(|(address, resource)| resource.resource_type().is_stealth() && *address != TARI_TOKEN)
        .map(|(address, _)| address)
        .expect("ballot resource");

    // Each voter spends their ballot UTXO directly into `cast_ballot`: the UTXO is a
    // key-path output whose spend key is its mask, so the spend transaction is signed with
    // the mask (the canonical in-process stealth-spend pattern).
    for (i, ranking) in rankings.iter().enumerate() {
        let ballot_spend = generate_transfer_data(
            [MaskAndValue {
                mask: ballot_mint.output_masks[i].clone(),
                value: 1,
            }],
            0u64,
            Vec::<u64>::new(),
            1u64,
        );
        let transaction = Transaction::builder_localnet(Epoch(100))
            .stealth_transfer(ballot_resource, ballot_spend.statement)
            .put_last_instruction_output_on_workspace("vote")
            .call_method(
                component,
                "cast_ballot",
                args![Workspace("vote"), ranking.to_vec()],
            )
            .finish()
            .add_signer(&test.to_public_key_bytes(), &ballot_mint.output_masks[i])
            .seal(test.secret_key());
        test.execute_expect_success(transaction, vec![]);
    }

    // A stealth UTXO can only be spent once: re-spending voter 0's ballot must fail.
    let double_spend = generate_transfer_data(
        [MaskAndValue {
            mask: ballot_mint.output_masks[0].clone(),
            value: 1,
        }],
        0u64,
        Vec::<u64>::new(),
        1u64,
    );
    let transaction = Transaction::builder_localnet(Epoch(100))
        .stealth_transfer(ballot_resource, double_spend.statement)
        .put_last_instruction_output_on_workspace("vote")
        .call_method(
            component,
            "cast_ballot",
            args![Workspace("vote"), rankings[0].to_vec()],
        )
        .finish()
        .add_signer(&test.to_public_key_bytes(), &ballot_mint.output_masks[0])
        .seal(test.secret_key());
    test.execute_expect_failure(transaction, vec![]);

    // End the vote: round 1 ties 1-1-1, candidate 0 is eliminated (lowest id), and voter 0's
    // second choice gives candidate 2 a 2/3 majority — the same expected winner as the
    // integration client.
    let transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&secret);
    let result = test.execute_expect_success(transaction, vec![]);
    let result_event = result
        .finalize
        .events
        .iter()
        .find(|event| event.topic().ends_with(".Result"))
        .expect("IRV tally event");
    assert_eq!(result_event.payload().get("winner"), Some("2"));
}

// ───────────────────── Method dispatch tests ─────────────────────
//
// These verify that the single `result` / `end_vote` / `end_vote_expired` entry points dispatch
// to the tally the election was configured with. The dispatch is observable through the events
// each tally emits: `Result` (IRV), `ResultFptp` (FPTP), `ResultMulti` (sequential IRV),
// `ResultStv` (STV).

/// Returns true if `topics` contains an event topic ending in `.<name>` (template events are
/// emitted with a `TemplateName.` prefix on their topic).
fn has_event(topics: &[String], name: &str) -> bool {
    let suffix = format!(".{name}");
    topics.iter().any(|t| t.ends_with(&suffix))
}

/// Runs `end_vote` on a freshly created component and returns the emitted event topics.
fn end_vote_topics(
    voter_count: u64,
    num_candidates: u32,
    num_winners: u32,
    tally_method: TallyMethod,
) -> Vec<String> {
    let (component, _ballot_resource, mut test, _account, _proof, secret) =
        create_vote(voter_count, num_candidates, num_winners, tally_method, 1000);
    let transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&secret);
    let result = test.execute_expect_success(transaction, vec![]);
    result
        .finalize
        .events
        .iter()
        .map(|event| event.topic().to_string())
        .collect()
}

#[test]
fn single_winner_vote_always_uses_irv() {
    // A single-winner election uses IRV regardless of the configured multi-winner method: the
    // method only applies to `num_winners > 1`.
    let topics = end_vote_topics(1, 3, 1, TallyMethod::SequentialIrv);
    assert!(
        has_event(&topics, "Result"),
        "expected an IRV tally event, got {topics:?}",
    );
    assert!(
        !has_event(&topics, "ResultMulti"),
        "sequential IRV must not run for a single-winner election, got {topics:?}",
    );
}

#[test]
fn single_winner_vote_ignores_stv_method() {
    let topics = end_vote_topics(1, 3, 1, TallyMethod::Stv);
    assert!(
        has_event(&topics, "Result"),
        "expected an IRV tally event, got {topics:?}",
    );
    assert!(
        !has_event(&topics, "ResultStv"),
        "STV must not run for a single-winner election, got {topics:?}",
    );
}

#[test]
fn multi_winner_vote_dispatches_sequential_irv() {
    let topics = end_vote_topics(1, 3, 2, TallyMethod::SequentialIrv);
    assert!(
        has_event(&topics, "ResultMulti"),
        "expected a sequential-IRV tally event, got {topics:?}",
    );
}

#[test]
fn multi_winner_vote_dispatches_stv() {
    let topics = end_vote_topics(1, 3, 2, TallyMethod::Stv);
    assert!(
        has_event(&topics, "ResultStv"),
        "expected an STV tally event, got {topics:?}",
    );
}

#[test]
fn fptp_vote_dispatches_fptp() {
    // An FPTP election runs the first-preference tally even though `num_winners == 1` would
    // otherwise fall back to IRV — FPTP is pinned at construction and takes precedence.
    let topics = end_vote_topics(1, 2, 1, TallyMethod::Fptp);
    assert!(
        has_event(&topics, "ResultFptp"),
        "expected an FPTP tally event, got {topics:?}",
    );
    assert!(
        !has_event(&topics, "Result"),
        "IRV must not run for an FPTP election, got {topics:?}",
    );
}

#[test]
fn fptp_yes_no_end_vote_returns_plurality_winner() {
    // Full template path for the yes/no use case: 2 candidates, 3 voters, candidate 0 wins 2-1.
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("RankedVote");
    let (_account, proof, secret) = test.create_funded_account();

    let choices: [[u32; 2]; 3] = [[0, 1], [0, 1], [1, 0]];

    // Create the vote; the constructor mints one amount-1 ballot UTXO per voter.
    let ballot_mint = mint_ballots(3);
    let transaction = test
        .transaction()
        .allocate_resource_address("ballot_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("ballot_res"),
                3u64,
                2u32,
                1u32,
                TallyMethod::Fptp,
                1000u64,
                ballot_mint.statement,
            ],
        )
        .build_and_seal(&secret);
    let result = test.execute_expect_success(transaction, vec![proof.clone()]);
    let component = result
        .finalize
        .result
        .accept()
        .unwrap()
        .up_iter()
        .find_map(|(id, _)| id.as_component_address())
        .expect("component address");
    let ballot_resource = test
        .read_only_state_store()
        .get_all_resources()
        .expect("resources")
        .into_iter()
        .find(|(address, resource)| resource.resource_type().is_stealth() && *address != TARI_TOKEN)
        .map(|(address, _)| address)
        .expect("ballot resource");

    // Each voter spends their ballot UTXO directly into `cast_ballot` (the canonical
    // in-process stealth-spend pattern, see `end_to_end_three_voter_election`).
    for (i, choice) in choices.iter().enumerate() {
        let ballot_spend = generate_transfer_data(
            [MaskAndValue {
                mask: ballot_mint.output_masks[i].clone(),
                value: 1,
            }],
            0u64,
            Vec::<u64>::new(),
            1u64,
        );
        let transaction = Transaction::builder_localnet(Epoch(100))
            .stealth_transfer(ballot_resource, ballot_spend.statement)
            .put_last_instruction_output_on_workspace("vote")
            .call_method(
                component,
                "cast_ballot",
                args![Workspace("vote"), choice.to_vec()],
            )
            .finish()
            .add_signer(&test.to_public_key_bytes(), &ballot_mint.output_masks[i])
            .seal(test.secret_key());
        test.execute_expect_success(transaction, vec![]);
    }

    // FPTP tally: candidate 0 ("yes") has 2 first-preference votes, candidate 1 ("no") has 1.
    let transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&secret);
    let result = test.execute_expect_success(transaction, vec![]);
    let result_event = result
        .finalize
        .events
        .iter()
        .find(|event| event.topic().ends_with(".ResultFptp"))
        .expect("FPTP tally event");
    assert_eq!(result_event.payload().get("winner"), Some("0"));
}

#[test]
fn rejects_fptp_with_multiple_winners() {
    // FPTP is single-winner by definition: counting first preferences for multiple seats would
    // not be a defined tally, so `new` rejects it outright.
    let reason = create_vote_expect_failure(1, 2, 2, TallyMethod::Fptp, 1000);
    assert_reject_reason(reason, "TallyMethod::Fptp is single-winner only");
}

#[test]
fn end_vote_rejected_for_non_initiator() {
    let (component, _ballot_resource, mut test, _account, _proof, secret) =
        create_vote(1, 2, 1, TallyMethod::SequentialIrv, 1000);

    // A different account (not the caller of `new`) tries to end the vote. The access rule on
    // `end_vote` requires the initiator's public key.
    let (_other_account, _other_proof, other_secret) = test.create_funded_account();
    let transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&other_secret);
    let reason = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(reason, "Access Denied");

    // The initiator can still end the vote, and the result is the IRV tally for a 1-winner
    // election.
    let transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&secret);
    let result = test.execute_expect_success(transaction, vec![]);
    assert!(
        result
            .finalize
            .events
            .iter()
            .any(|event| event.topic().ends_with(".Result")),
        "expected an IRV tally event after the initiator ends the vote",
    );
}
