// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{bool_set::BoolSet, meta_vote_counts::MetaVoteCounts};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
};

// This holds the state of a (binary) meta vote about which we're trying to achieve consensus.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MetaVote {
    pub round: usize,
    pub step: Step,
    pub estimates: BoolSet,
    pub bin_values: BoolSet,
    pub aux_value: Option<bool>,
    pub decision: Option<bool>,
}

fn write_bool(f: &mut Formatter<'_>, a_bool: bool) -> fmt::Result {
    if a_bool {
        write!(f, "t")
    } else {
        write!(f, "f")
    }
}

fn write_multiple_bool_values(f: &mut Formatter<'_>, field: &str, input: BoolSet) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    match input {
        BoolSet::Empty => (),
        BoolSet::Single(ref s) => {
            write_bool(f, *s)?;
        }
        BoolSet::Both => {
            write_bool(f, true)?;
            write!(f, ", ")?;
            write_bool(f, false)?;
        }
    }
    write!(f, "}} ")
}

fn write_optional_single_bool_value(
    f: &mut Formatter<'_>,
    field: &str,
    value: Option<bool>,
) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    if let Some(vote) = value {
        write_bool(f, vote)?;
    }
    write!(f, "}} ")
}

impl Debug for MetaVote {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{{ {}/{:?}, ", self.round, self.step)?;

        write_multiple_bool_values(f, "est", self.estimates)?;
        write_multiple_bool_values(f, "bin", self.bin_values)?;
        write_optional_single_bool_value(f, "aux", self.aux_value)?;
        write_optional_single_bool_value(f, "dec", self.decision)?;

        write!(f, "}}")
    }
}

impl MetaVote {
    pub fn new(
        initial_estimate: bool,
        others: &[&[MetaVote]],
        total_peers: usize,
        is_voter: bool,
    ) -> Vec<Self> {
        let mut initial = Self::default();
        if is_voter {
            initial.estimates = BoolSet::from_bool(initial_estimate);
        }
        Self::next_votes(&[initial], others, &BTreeMap::new(), total_peers, is_voter)
    }

    /// Create temporary next meta-votes. They must be finalized by calling `next_final` before
    /// passing them to `MetaEvent`.
    pub fn next_temp(
        parent: &[MetaVote],
        others: &[&[MetaVote]],
        total_peers: usize,
        is_voter: bool,
    ) -> Vec<Self> {
        Self::next_votes(parent, others, &BTreeMap::new(), total_peers, is_voter)
    }

    /// Finalize temporary meta-votes.
    pub fn next_final(
        temp: &[MetaVote],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
        is_voter: bool,
    ) -> Vec<Self> {
        Self::next_votes(temp, &[], coin_tosses, total_peers, is_voter)
    }

    fn next_votes(
        prev: &[MetaVote],
        others: &[&[MetaVote]],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
        is_voter: bool,
    ) -> Vec<Self> {
        let mut next = Vec::new();
        for vote in prev {
            let counts = MetaVoteCounts::new(vote, others, total_peers, is_voter);
            let updated = vote.update(counts, &coin_tosses, is_voter);
            let decided = updated.decision.is_some();
            next.push(updated);
            if decided {
                break;
            }
        }

        while let Some(next_meta_vote) =
            Self::next_vote(next.last(), others, &coin_tosses, total_peers, is_voter)
        {
            next.push(next_meta_vote);
        }

        next
    }

    pub fn round_and_step(&self) -> (usize, Step) {
        (self.round, self.step)
    }

    fn update(
        &self,
        mut counts: MetaVoteCounts,
        coin_tosses: &BTreeMap<usize, bool>,
        is_voter: bool,
    ) -> MetaVote {
        if self.decision.is_some() {
            return *self;
        }
        let coin_toss = coin_tosses.get(&self.round);
        let mut updated = *self;
        updated.calculate_new_estimates(&mut counts, coin_toss, is_voter);
        let bin_values_was_empty = updated.bin_values.is_empty();
        updated.calculate_new_bin_values(&mut counts, is_voter);
        updated.calculate_new_auxiliary_value(&mut counts, bin_values_was_empty, is_voter);
        counts.check_exceeding();
        updated.calculate_new_decision(&counts);
        updated
    }

    fn next_vote(
        parent: Option<&Self>,
        others: &[&[MetaVote]],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
        is_voter: bool,
    ) -> Option<MetaVote> {
        let parent = parent?;

        if parent.decision.is_some() {
            return None;
        }
        let counts = MetaVoteCounts::new(parent, others, total_peers, is_voter);
        if counts.is_supermajority(counts.aux_values_set()) {
            let coin_toss = coin_tosses.get(&parent.round);
            let next = parent.increase_step(&counts, coin_toss.cloned());
            let new_counts = MetaVoteCounts::new(&next, others, total_peers, is_voter);
            let updated = next.update(new_counts, &coin_tosses, is_voter);
            Some(updated)
        } else {
            None
        }
    }

    fn calculate_new_estimates(
        &mut self,
        counts: &mut MetaVoteCounts,
        coin_toss: Option<&bool>,
        is_voter: bool,
    ) {
        if self.estimates.is_empty() {
            if let Some(toss) = coin_toss {
                if is_voter {
                    if *toss {
                        counts.estimates_true += 1;
                    } else {
                        counts.estimates_false += 1;
                    }
                }
                self.estimates = BoolSet::from_bool(*toss);
            }
        } else {
            if counts.at_least_one_third(counts.estimates_true)
                && self.estimates.insert(true)
                && is_voter
            {
                counts.estimates_true += 1;
            }
            if counts.at_least_one_third(counts.estimates_false)
                && self.estimates.insert(false)
                && is_voter
            {
                counts.estimates_false += 1;
            }
        }
    }

    fn calculate_new_bin_values(&mut self, counts: &mut MetaVoteCounts, is_voter: bool) {
        if counts.is_supermajority(counts.estimates_true)
            && self.bin_values.insert(true)
            && is_voter
        {
            counts.bin_values_true += 1;
        }
        if counts.is_supermajority(counts.estimates_false)
            && self.bin_values.insert(false)
            && is_voter
        {
            counts.bin_values_false += 1;
        }
    }

    fn calculate_new_auxiliary_value(
        &mut self,
        counts: &mut MetaVoteCounts,
        bin_values_was_empty: bool,
        is_voter: bool,
    ) {
        if self.aux_value.is_some() {
            return;
        }
        if bin_values_was_empty {
            if self.bin_values.len() == 1 {
                if self.bin_values.contains(true) {
                    self.aux_value = Some(true);
                    if is_voter {
                        counts.aux_values_true += 1;
                    }
                } else {
                    self.aux_value = Some(false);
                    if is_voter {
                        counts.aux_values_false += 1;
                    }
                }
            } else if self.bin_values.len() == 2 {
                self.aux_value = Some(true);
                if is_voter {
                    counts.aux_values_true += 1;
                }
            }
        }
    }

    fn calculate_new_decision(&mut self, counts: &MetaVoteCounts) {
        let opt_decision = match self.step {
            Step::ForcedTrue => {
                if self.bin_values.contains(true) && counts.is_supermajority(counts.aux_values_true)
                {
                    Some(true)
                } else {
                    counts.decision
                }
            }
            Step::ForcedFalse => {
                if self.bin_values.contains(false)
                    && counts.is_supermajority(counts.aux_values_false)
                {
                    Some(false)
                } else {
                    counts.decision
                }
            }
            Step::GenuineFlip => counts.decision,
        };
        if let Some(decision) = opt_decision {
            self.estimates = BoolSet::from_bool(decision);
            self.bin_values = BoolSet::from_bool(decision);
            self.aux_value = Some(decision);
            self.decision = Some(decision);
        }
    }

    fn increase_step(&self, counts: &MetaVoteCounts, coin_toss: Option<bool>) -> Self {
        let mut next = Self {
            bin_values: BoolSet::Empty,
            aux_value: None,
            ..*self
        };

        // Set the estimates as per the concrete coin toss rules.
        match next.step {
            Step::ForcedTrue => {
                if counts.is_supermajority(counts.aux_values_false) {
                    next.estimates = BoolSet::from_bool(false);
                } else if !counts.is_supermajority(counts.aux_values_true) {
                    next.estimates = BoolSet::from_bool(true);
                }
                next.step = Step::ForcedFalse;
            }
            Step::ForcedFalse => {
                if counts.is_supermajority(counts.aux_values_true) {
                    next.estimates = BoolSet::from_bool(true);
                } else if !counts.is_supermajority(counts.aux_values_false) {
                    next.estimates = BoolSet::from_bool(false);
                }
                next.step = Step::GenuineFlip;
            }
            Step::GenuineFlip => {
                if counts.is_supermajority(counts.aux_values_true) {
                    next.estimates = BoolSet::from_bool(true);
                } else if counts.is_supermajority(counts.aux_values_false) {
                    next.estimates = BoolSet::from_bool(false);
                } else if let Some(coin_toss_result) = coin_toss {
                    next.estimates = BoolSet::from_bool(coin_toss_result);
                } else {
                    // Clear the estimates to indicate we're waiting for further events to be
                    // gossiped to try and get the coin toss result.
                    next.estimates.clear();
                }
                next.step = Step::ForcedTrue;
                next.round += 1;
            }
        }

        next
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) enum Step {
    ForcedTrue,
    ForcedFalse,
    GenuineFlip,
}

impl Default for Step {
    fn default() -> Step {
        Step::ForcedTrue
    }
}

impl Debug for Step {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let step = match self {
            Step::ForcedTrue => 0,
            Step::ForcedFalse => 1,
            Step::GenuineFlip => 2,
        };
        write!(f, "{}", step)
    }
}
