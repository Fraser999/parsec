// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
use error::Error;
use gossip::{Event, Request, Response};
use hash::Hash;
use id::SecretId;
use meta_vote::MetaVote;
use network_event::NetworkEvent;
use peer_manager::PeerManager;
use round_hash::RoundHash;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_manager: PeerManager<S>,
    // Gossip events created locally and received from other peers.
    events: BTreeMap<Hash, Event<T, S::PublicId>>,
    // The sequence in which all gossip events were added to this `Parsec`.
    events_order: Vec<Hash>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    // The meta votes of the events.
    meta_votes: BTreeMap<Hash, BTreeMap<S::PublicId, MetaVote>>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<S::PublicId, Vec<RoundHash>>,
    responsiveness_threshold: usize,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs.
    pub fn new(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Result<Self, Error> {
        let responsiveness_threshold = (genesis_group.len() as f64).log2().ceil() as usize;

        let mut peer_manager = PeerManager::new(our_id);
        for peer_id in genesis_group.iter() {
            peer_manager.add_peer(peer_id.clone());
        }

        let mut parsec = Parsec {
            peer_manager,
            events: BTreeMap::new(),
            events_order: vec![],
            consensused_blocks: VecDeque::new(),
            meta_votes: BTreeMap::new(),
            round_hashes: BTreeMap::new(),
            responsiveness_threshold,
        };
        let initial_event = Event::new_initial(parsec.peer_manager.our_id())?;
        parsec.add_initial_event(initial_event)?;
        Ok(parsec)
    }

    /// Add a vote for `network_event`.
    pub fn vote_for(&mut self, network_event: T) -> Result<(), Error> {
        let our_pub_id = self.peer_manager.our_id().public_id().clone();
        let self_parent_hash =
            if let Some(last_hash) = self.peer_manager.last_event_hash(&our_pub_id) {
                *last_hash
            } else {
                return Err(Error::InvalidEvent);
            };
        let event = Event::new_from_observation(
            self.peer_manager.our_id(),
            self_parent_hash,
            network_event,
        )?;
        self.add_event(event)
    }

    /// Creates a new message to be gossiped to a random peer.
    pub fn create_gossip(&self) -> Request<T, S::PublicId> {
        Request::new(
            self.events_order
                .iter()
                .filter_map(|hash| self.events.get(hash)),
        )
    }

    /// Handles a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>, Error> {
        for event in req.unpack() {
            self.add_event(event)?;
        }
        self.create_sync_event(src, true)?;

        // Return all the events we think `src` doesn't yet know about, packed into a `Response`.
        let other_parent_hash = self.peer_manager.last_event_hash(src).ok_or(Error::Logic)?;
        let other_parent = self.events.get(other_parent_hash).ok_or(Error::Logic)?;
        let last_ancestors_hashes = other_parent
            .last_ancestors
            .iter()
            .filter_map(|(peer_id, &index)| self.peer_manager.event_by_index(peer_id, index))
            .collect::<BTreeSet<_>>();
        let response_events_iter = self
            .events_order
            .iter()
            .skip_while(|hash| !last_ancestors_hashes.contains(hash))
            .filter_map(|hash| self.events.get(hash));
        Ok(Response::new(response_events_iter))
    }

    /// Handles a received `Response` from `src` peer.  Returns `Err` if the response was not valid.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        for event in resp.unpack() {
            self.add_event(event)?;
        }
        self.create_sync_event(src, false)
    }

    /// Steps the algorithm and returns the next stable block, if any.
    pub fn poll(&mut self) -> Result<Option<Block<T, S::PublicId>>, Error> {
        unimplemented!();
    }

    /// Checks if the given `network_event` has already been voted for by us.
    pub fn have_voted_for(&self, network_event: &T) -> bool {
        let our_pub_id = self.peer_manager.our_id().public_id();
        self.events.values().any(|event| {
            if event.creator() == our_pub_id {
                if let Some(voted) = event.vote() {
                    voted.payload() == network_event
                } else {
                    false
                }
            } else {
                false
            }
        })
    }

    fn self_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.self_parent().and_then(|hash| self.events.get(hash))
    }

    fn other_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.other_parent().and_then(|hash| self.events.get(hash))
    }

    fn is_observer(&self, event: &Event<T, S::PublicId>) -> bool {
        self.peer_manager
            .is_super_majority(event.observations.len())
    }

    fn add_event(&mut self, mut event: Event<T, S::PublicId>) -> Result<(), Error> {
        if self.events.contains_key(event.hash()) {
            return Ok(());
        }

        if self.self_parent(&event).is_none() {
            if event.is_initial() {
                return self.add_initial_event(event);
            } else {
                return Err(Error::UnknownParent);
            }
        }

        if let Some(hash) = event.other_parent() {
            if !self.events.contains_key(hash) {
                return Err(Error::UnknownParent);
            }
        }

        self.set_index(&mut event);
        self.peer_manager.add_event(&event)?;
        self.set_last_ancestors(&mut event)?;
        self.set_first_descendants(&mut event)?;
        self.set_valid_blocks_carried(&mut event)?;

        let event_hash = *event.hash();
        self.events_order.push(event_hash);
        let _ = self.events.insert(event_hash, event);
        self.process_event(&event_hash)
    }

    fn add_initial_event(&mut self, mut event: Event<T, S::PublicId>) -> Result<(), Error> {
        event.index = Some(0);
        let creator_id = event.creator().clone();
        let _ = event.first_descendants.insert(creator_id, 0);
        let event_hash = *event.hash();
        self.peer_manager.add_event(&event)?;
        self.events_order.push(event_hash);
        let _ = self.events.insert(event_hash, event);
        Ok(())
    }

    fn process_event(&mut self, event_hash: &Hash) -> Result<(), Error> {
        self.set_observations(event_hash)?;
        self.set_meta_votes(event_hash)?;
        if let Some(block) = self.next_stable_block() {
            self.clear_consensus_data(block.payload());
            self.consensused_blocks.push_back(block);
            self.restart_consensus();
        }
        Ok(())
    }

    fn set_index(&self, event: &mut Event<T, S::PublicId>) {
        event.index = Some(
            self.self_parent(event)
                .and_then(|parent| parent.index)
                .map_or(0, |index| index + 1),
        );
    }

    // This should only be called once `event` has had its `index` set correctly.
    fn set_last_ancestors(&self, event: &mut Event<T, S::PublicId>) -> Result<(), Error> {
        let event_index = if let Some(index) = event.index {
            index
        } else {
            return Err(Error::InvalidEvent);
        };

        if let Some(self_parent) = self.self_parent(event) {
            event.last_ancestors = self_parent.last_ancestors.clone();

            if let Some(other_parent) = self.other_parent(event) {
                for (peer_id, _) in self.peer_manager.iter() {
                    if let Some(other_index) = other_parent.last_ancestors.get(peer_id) {
                        let existing_index = event
                            .last_ancestors
                            .entry(peer_id.clone())
                            .or_insert(*other_index);
                        if *existing_index < *other_index {
                            *existing_index = *other_index;
                        }
                    }
                }
            }
        } else if self.other_parent(event).is_some() {
            // If we have no self-parent, we should also have no other-parent.
            return Err(Error::InvalidEvent);
        }

        let creator_id = event.creator().clone();
        let _ = event.last_ancestors.insert(creator_id, event_index);
        Ok(())
    }

    // This should be called only once `event` has had its `index` and `last_ancestors` set
    // correctly (i.e. after calling `Parsec::set_last_ancestors()` on it)
    fn set_first_descendants(&mut self, event: &mut Event<T, S::PublicId>) -> Result<(), Error> {
        if event.last_ancestors.is_empty() {
            return Err(Error::InvalidEvent);
        }

        let event_index = if let Some(index) = event.index {
            index
        } else {
            return Err(Error::InvalidEvent);
        };
        let creator_id = event.creator().clone();
        let _ = event.first_descendants.insert(creator_id, event_index);

        for (peer_id, peer_info) in self.peer_manager.iter() {
            let mut opt_hash = event
                .last_ancestors
                .get(peer_id)
                .and_then(|index| peer_info.get(index))
                .cloned();

            loop {
                if let Some(hash) = opt_hash {
                    if let Some(other_event) = self.events.get_mut(&hash) {
                        if !other_event.first_descendants.contains_key(event.creator()) {
                            let _ = other_event
                                .first_descendants
                                .insert(event.creator().clone(), event_index);
                            opt_hash = other_event.self_parent().cloned();
                            continue;
                        }
                    }
                }
                break;
            }
        }

        Ok(())
    }

    fn set_valid_blocks_carried(&mut self, event: &mut Event<T, S::PublicId>) -> Result<(), Error> {
        // If this node already has meta votes running, no need to calculate `valid_blocks_carried`.
        if self
            .self_parent(event)
            .and_then(|parent| self.meta_votes.get(parent.hash()))
            .is_some()
        {
            return Ok(());
        }
        // Union of
        // * my self_parent's valid_blocks_carried,
        // * my other_parent's valid_blocks_carried,
        // * any observation I made that makes a block valid
        // Note that if any block becomes stable due to this gossip event, we will learn
        // that fact later and prune valid_blocks_carried accordingly
        let self_parents_valid_blocks = {
            if let Some(self_parent) = self.self_parent(event) {
                self_parent.valid_blocks_carried.clone()
            } else {
                BTreeSet::new()
            }
        };
        let other_parents_valid_blocks = {
            if let Some(other_parent) = self.other_parent(event) {
                other_parent.valid_blocks_carried.clone()
            } else {
                BTreeSet::new()
            }
        };
        let blocks_made_valid_now = {
            if let Some(vote) = event.vote() {
                let mut valid_votes: BTreeSet<Hash> = BTreeSet::new();
                let n_same_votes = self
                    .events
                    .iter()
                    .filter(|(_, value)| (**value).vote() == Some(vote))
                    .count();
                if self.peer_manager.is_super_majority(n_same_votes)
                    && !valid_votes.insert(event.hash().clone())
                {
                    return Err(Error::InvalidEvent);
                }
                valid_votes
            } else {
                BTreeSet::new()
            }
        };
        event.valid_blocks_carried = self_parents_valid_blocks
            .union(&other_parents_valid_blocks)
            .cloned()
            .collect::<BTreeSet<_>>()
            .union(&blocks_made_valid_now)
            .cloned()
            .collect();
        Ok(())
    }

    fn last_event(&self, peer_id: &S::PublicId) -> Option<&Event<T, S::PublicId>> {
        let last_hash = self.peer_manager.last_event_hash(peer_id);
        match last_hash {
            Some(hash) => Some(&self.events[hash]),
            None => None,
        }
    }

    fn oldest_event_with_valid_block(
        &self,
        peer_id: &S::PublicId,
    ) -> Option<&Event<T, S::PublicId>> {
        match self.last_event(peer_id) {
            Some(last_event) => (*last_event)
                .valid_blocks_carried
                .iter()
                .map(|hash| &self.events[hash])
                .min_by(|lhs_event, rhs_event| {
                    let lhs_index = lhs_event.index.unwrap_or(u64::max_value());
                    let rhs_index = rhs_event.index.unwrap_or(u64::max_value());
                    lhs_index.cmp(&rhs_index)
                }),
            None => None,
        }
    }

    fn set_observations(&mut self, event_hash: &Hash) -> Result<(), Error> {
        // If this node already has meta votes running, no need to calculate `observations`.
        if self
            .self_parent(self.events.get(event_hash).ok_or(Error::Logic)?)
            .and_then(|parent| self.meta_votes.get(parent.hash()))
            .is_some()
        {
            return Ok(());
        }
        // Grab latest event from each peer
        // If they can strongly see an event that carries a valid block, add the peer's public id
        let observations = self
            .peer_manager
            .all_ids()
            .into_iter()
            .filter(|peer| match self.oldest_event_with_valid_block(peer) {
                Some(event) => match self.last_event(peer) {
                    Some(last_event) => self.does_strongly_see(event, last_event),
                    None => false,
                },
                None => false,
            })
            .cloned()
            .collect();
        let event = self.events.get_mut(event_hash).ok_or(Error::Logic)?;
        event.observations = observations;
        Ok(())
    }

    fn set_meta_votes(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let total_peers = self.peer_manager.iter().count();
        let mut meta_votes = BTreeMap::new();
        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        let event_hash = if let Some(parent_votes) = self
            .self_parent(self.events.get(event_hash).ok_or(Error::Logic)?)
            .and_then(|parent| self.meta_votes.get(parent.hash()).cloned())
        {
            let event = self.events.get(event_hash).ok_or(Error::Logic)?;
            for (peer_id, parent_vote) in parent_votes {
                let coin_toss = self.toss_coin(&peer_id, &parent_vote, event);
                let other_votes = if parent_vote.estimates.is_empty() {
                    // If `estimates` is empty, we've been waiting for the result of a coin toss.
                    // In that case, we don't care about other votes, we just need the coin toss
                    // result.
                    vec![]
                } else {
                    self.collect_other_meta_votes(
                        &peer_id,
                        parent_vote.round,
                        parent_vote.step,
                        event,
                    )
                };
                let meta_vote = MetaVote::next(&parent_vote, &other_votes, coin_toss, total_peers);
                if let Some(hashes) = self.round_hashes.get_mut(&peer_id) {
                    while hashes.len() < meta_vote.round + 1 {
                        let next_round_hash = hashes[hashes.len() - 1].next()?;
                        hashes.push(next_round_hash);
                    }
                }
                let _ = meta_votes.insert(peer_id, meta_vote);
            }
            *event.hash()
        } else {
            let event = self.events.get(event_hash).ok_or(Error::Logic)?;
            if self.is_observer(event) {
                // Start meta votes for this event.
                for peer_id in self.peer_manager.all_ids() {
                    let other_votes = self.collect_other_meta_votes(peer_id, 0, 0, event);
                    let initial_estimate = event.observations.contains(peer_id);
                    let _ = meta_votes.insert(
                        peer_id.clone(),
                        MetaVote::new(initial_estimate, &other_votes, total_peers),
                    );
                }
            }
            *event.hash()
        };

        if !meta_votes.is_empty() {
            let _ = self.meta_votes.insert(event_hash, meta_votes);
        }

        Ok(())
    }

    fn toss_coin(
        &self,
        peer_id: &S::PublicId,
        parent_vote: &MetaVote,
        event: &Event<T, S::PublicId>,
    ) -> Option<bool> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            parent_vote.round - 1
        } else if parent_vote.step == 2 {
            parent_vote.round
        } else {
            return None;
        };
        let round_hash = if let Some(hashes) = self.round_hashes.get(peer_id) {
            hashes[round].value()
        } else {
            // Should be unreachable.
            return None;
        };

        // Get the gradient of leadership.
        let mut peer_id_hashes = self.peer_manager.peer_id_hashes().clone();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.0, &rhs.0));

        // Try to get the "most-leader"'s aux value.
        let creator = &peer_id_hashes[0].1;
        if let Some(creator_event_index) = event.last_ancestors.get(creator) {
            if let Some(aux_value) = self.aux_value(creator, *creator_event_index, peer_id, round) {
                return Some(aux_value);
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(peer_id, round, event) {
            for (_, creator) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors.get(creator) {
                    if let Some(aux_value) =
                        self.aux_value(creator, *creator_event_index, peer_id, round)
                    {
                        return Some(aux_value);
                    }
                }
            }
        }

        None
    }

    // Returns the aux value for the given peer, created by `creator`, at the given round and at
    // step 2.
    fn aux_value(
        &self,
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
    ) -> Option<bool> {
        self.most_recent_meta_vote(creator, creator_event_index, peer_id, round, 2)
            .and_then(|meta_vote| meta_vote.aux_value)
    }

    // Skips back through our events until we've passed `responsiveness_threshold` response events
    // and sees if we were waiting for this coin toss result then too.  If so, returns `true`.
    fn stop_waiting(
        &self,
        peer_id: &S::PublicId,
        round: usize,
        event: &Event<T, S::PublicId>,
    ) -> bool {
        let mut response_count = 0;
        let mut event_hash = *event.hash();
        while response_count < self.responsiveness_threshold {
            if let Some(evnt) = self.self_parent(event) {
                if evnt.is_response() {
                    response_count += 1;
                    event_hash = *evnt.hash();
                }
            } else {
                return false;
            }
        }

        if let Some(meta_vote) = self
            .meta_votes
            .get(&event_hash)
            .and_then(|meta_votes| meta_votes.get(peer_id))
        {
            // If we're waiting for a coin toss result, `estimates` is empty, and for that meta
            // vote, the round has already been incremented by 1.
            meta_vote.estimates.is_empty() && meta_vote.round == round + 1
        } else {
            false
        }
    }

    // Returns the meta vote for the given peer, created by `creator`, at the given round and step.
    // Starts iterating down the creator's events starting from `creator_event_index`.
    fn most_recent_meta_vote(
        &self,
        creator: &S::PublicId,
        mut creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
        step: usize,
    ) -> Option<&MetaVote> {
        loop {
            let event_hash = self
                .peer_manager
                .event_by_index(creator, creator_event_index)?;
            let meta_vote = self
                .meta_votes
                .get(event_hash)
                .and_then(|meta_votes| meta_votes.get(peer_id))?;
            if meta_vote.round == round && meta_vote.step == step {
                return Some(meta_vote);
            }
            if meta_vote.round > round && creator_event_index != 0 {
                creator_event_index -= 1;
            } else {
                break;
            }
        }
        None
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by `peer_id` at the given `round` and `step`.
    fn collect_other_meta_votes(
        &self,
        peer_id: &S::PublicId,
        round: usize,
        step: usize,
        event: &Event<T, S::PublicId>,
    ) -> Vec<MetaVote> {
        let mut other_votes = vec![];
        for creator in self.peer_manager.all_ids() {
            if let Some(meta_vote) = event.last_ancestors.get(creator).and_then(
                |creator_event_index| {
                    self.most_recent_meta_vote(creator, *creator_event_index, &peer_id, round, step)
                        .cloned()
                },
            ) {
                other_votes.push(meta_vote)
            }
        }
        other_votes
    }

    fn next_stable_block(&mut self) -> Option<Block<T, S::PublicId>> {
        let us = self.peer_manager.our_id().public_id();
        self.peer_manager
            .last_event_hash(us)
            .and_then(|our_last_event| {
                let our_decided_meta_votes = self.meta_votes[our_last_event]
                    .iter()
                    .filter(|(_id, vote)| vote.decision.is_some());
                if our_decided_meta_votes.clone().count() < self.peer_manager.all_ids().len() {
                    None
                } else {
                    let mut elected_gossip_events = our_decided_meta_votes
                        .filter_map(|(id, vote)| {
                            if vote.decision == Some(true) {
                                self.oldest_event_with_valid_block(id)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    // We sort the events by their vote to avoid ties when picking the event
                    // with the most represented payload.
                    // Because `max_by` guarentees that "If several elements are equally
                    // maximum, the last element is returned.", this should be enough to break
                    // any tie.
                    elected_gossip_events.sort_by(|lhs, rhs| lhs.vote().cmp(&rhs.vote()));

                    let votes = elected_gossip_events
                        .iter()
                        .map(|event| event.vote())
                        .collect::<Vec<_>>();
                    let copied_votes = votes.clone();
                    let winning_vote = copied_votes
                        .iter()
                        .max_by(|lhs_event, rhs_event| {
                            let lhs_count = votes
                                .iter()
                                .filter(|vote| {
                                    vote.map(|x| x.payload()) == lhs_event.map(|x| x.payload())
                                })
                                .count();
                            let rhs_count = votes
                                .iter()
                                .filter(|vote| {
                                    vote.map(|x| x.payload()) == rhs_event.map(|x| x.payload())
                                })
                                .count();
                            lhs_count.cmp(&rhs_count)
                        })
                        .unwrap_or(&None);
                    let votes = elected_gossip_events
                        .iter()
                        .flat_map(|event| event.valid_blocks_carried.clone())
                        .map(|hash| &self.events[&hash])
                        .filter_map(|event| {
                            if event.vote() == *winning_vote {
                                event
                                    .vote()
                                    .map(|vote| (event.creator().clone(), vote.clone()))
                            } else {
                                None
                            }
                        })
                        .collect::<BTreeMap<_, _>>();
                    winning_vote.and_then(|vote| Block::new(vote.payload().clone(), &votes).ok())
                }
            })
    }

    fn clear_consensus_data(&mut self, payload: &T) {
        // Clear all leftover data from previous consensus
        self.round_hashes = BTreeMap::new();
        self.meta_votes = BTreeMap::new();
        let stable_blocks_carried: BTreeSet<Hash> = self
            .events
            .iter()
            .filter_map(|(hash, event)| {
                if event.vote().map(|vote| vote.payload()) == Some(payload) {
                    Some(*hash)
                } else {
                    None
                }
            })
            .collect();
        self.events.iter_mut().for_each(|(_hash, event)| {
            event.observations = BTreeSet::new();
            let stable_blocks_carried = event
                .valid_blocks_carried
                .iter()
                .filter(|hash| stable_blocks_carried.contains(&hash))
                .cloned()
                .collect::<BTreeSet<Hash>>();
            event.valid_blocks_carried = event
                .valid_blocks_carried
                .difference(&stable_blocks_carried)
                .cloned()
                .collect();
        });
    }

    fn restart_consensus(&mut self) {
        // Start from the oldest event with a valid block considering all creators' events.
        let all_oldest_events_with_valid_block = self
            .peer_manager
            .all_ids()
            .iter()
            .filter_map(|peer_id| self.oldest_event_with_valid_block(peer_id).map(Event::hash))
            .cloned()
            .collect::<BTreeSet<_>>();
        let events_hashes = self
            .events_order
            .iter()
            .skip_while(|hash| !all_oldest_events_with_valid_block.contains(hash))
            .cloned()
            .collect::<Vec<_>>();
        for event_hash in &events_hashes {
            let _ = self.process_event(event_hash);
        }
    }

    // Returns whether event X can strongly see the event Y.
    fn does_strongly_see(&self, x: &Event<T, S::PublicId>, y: &Event<T, S::PublicId>) -> bool {
        let count = y
            .first_descendants
            .iter()
            .filter(|(peer_id, descendant)| {
                x.last_ancestors
                    .get(&peer_id)
                    .map(|last_ancestor| last_ancestor >= *descendant)
                    .unwrap_or(false)
            })
            .count();

        self.peer_manager.is_super_majority(count)
    }

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    fn create_sync_event(&mut self, src: &S::PublicId, is_request: bool) -> Result<(), Error> {
        let self_parent = *self
            .peer_manager
            .last_event_hash(self.peer_manager.our_id().public_id())
            .ok_or(Error::Logic)?;
        let other_parent = *self.peer_manager.last_event_hash(src).ok_or(Error::Logic)?;
        let sync_event = if is_request {
            Event::new_from_request(self.peer_manager.our_id(), self_parent, other_parent)
        } else {
            Event::new_from_response(self.peer_manager.our_id(), self_parent, other_parent)
        }?;
        self.add_event(sync_event)
    }
}
