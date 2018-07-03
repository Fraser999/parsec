// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
use dump_network::dump_gossip_graph;
use error::Error;
use gossip::{Event, Request, Response};
use hash::Hash;
use id::SecretId;
use maidsafe_utilities::serialisation::serialise;
use meta_vote::{MetaVote, Step};
use network_event::NetworkEvent;
use peer_manager::PeerManager;
use round_hash::RoundHash;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug, Formatter};

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
    // Hash of all payloads that were consensused ever
    consensus_history: Vec<Hash>,
    // The meta votes of the events.
    meta_votes: BTreeMap<Hash, BTreeMap<S::PublicId, Vec<MetaVote>>>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<S::PublicId, Vec<RoundHash>>,
    responsiveness_threshold: usize,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    pub fn new(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Result<Self, Error> {
        let responsiveness_threshold = (genesis_group.len() as f64).log2().ceil() as usize;

        let mut peer_manager = PeerManager::new(our_id);
        let mut round_hashes = BTreeMap::new();
        let initial_hash = Hash::from([].as_ref());
        for peer_id in genesis_group.iter().cloned() {
            peer_manager.add_peer(peer_id.clone());
            let round_hash = RoundHash::new(&peer_id, initial_hash)?;
            let _ = round_hashes.insert(peer_id, vec![round_hash]);
        }

        let mut parsec = Parsec {
            peer_manager,
            events: BTreeMap::new(),
            events_order: vec![],
            consensused_blocks: VecDeque::new(),
            consensus_history: vec![],
            meta_votes: BTreeMap::new(),
            round_hashes,
            responsiveness_threshold,
        };
        let initial_event = Event::new_initial(parsec.peer_manager.our_id())?;
        parsec.add_initial_event(initial_event)?;
        Ok(parsec)
    }

    /// Adds a vote for `network_event`.  Returns an error if we have already voted for this.
    pub fn vote_for(&mut self, network_event: T) -> Result<(), Error> {
        if self.have_voted_for(&network_event) {
            return Err(Error::DuplicateVote);
        }
        let self_parent_hash = self.our_last_event_hash().ok_or(Error::InvalidEvent)?;
        let event = Event::new_from_observation(
            self.peer_manager.our_id(),
            self_parent_hash,
            network_event,
        )?;
        self.add_event(event)
    }

    /// Creates a new message to be gossiped to a peer containing all gossip events this node thinks
    /// that peer needs.  If `peer_id` is `None`, a message containing all known gossip events is
    /// returned.  If `peer_id` is `Some` and the given peer is unknown to this node, an error is
    /// returned.
    pub fn create_gossip(
        &self,
        peer_id: Option<S::PublicId>,
    ) -> Result<Request<T, S::PublicId>, Error> {
        if let Some(recipient_id) = peer_id {
            if !self.peer_manager.has_peer(&recipient_id) {
                return Err(Error::UnknownPeer);
            }
            if self.peer_manager.last_event_hash(&recipient_id).is_some() {
                return self
                    .events_to_gossip_to_peer(&recipient_id)
                    .map(Request::new);
            }
        }
        Ok(Request::new(
            self.events_order
                .iter()
                .filter_map(|hash| self.events.get(hash)),
        ))
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
        self.events_to_gossip_to_peer(src).map(Response::new)
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
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Checks if the given `network_event` has already been voted for by us.
    pub fn have_voted_for(&self, network_event: &T) -> bool {
        self.events.values().any(|event| {
            event.creator() == self.our_pub_id()
                && event
                    .vote()
                    .map_or(false, |voted| voted.payload() == network_event)
        })
    }

    fn our_pub_id(&self) -> &S::PublicId {
        self.peer_manager.our_id().public_id()
    }

    fn our_last_event_hash(&self) -> Option<Hash> {
        self.peer_manager
            .last_event_hash(self.our_pub_id())
            .cloned()
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
        self.update_round_hashes(event_hash)?;
        if let Some(block) = self.next_stable_block() {
            self.clear_consensus_data(block.payload())?;
            let block_hash = Hash::from(serialise(&block)?.as_slice());
            let payload_hash = Hash::from(serialise(block.payload())?.as_slice());
            self.consensus_history.push(payload_hash);
            self.consensused_blocks.push_back(block);
            self.restart_consensus(&block_hash)?;
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
        let event_index = event.index.ok_or(Error::InvalidEvent)?;

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

        let event_index = event.index.ok_or(Error::InvalidEvent)?;
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

    fn set_valid_blocks_carried(&self, event: &mut Event<T, S::PublicId>) -> Result<(), Error> {
        // If my self_parent already carries a valid block for this peer, use it
        if let Some(self_parent) = self.self_parent(event) {
            event
                .valid_blocks_carried
                .append(&mut self_parent.valid_blocks_carried.clone())
        }
        // If my other_parent already carries a valid block for this peer, use it
        if let Some(other_parent) = self.other_parent(event) {
            event
                .valid_blocks_carried
                .append(&mut other_parent.valid_blocks_carried.clone())
        }
        // If none of my parents already carries a valid block for this peer, see if this event
        // makes a block valid
        if event.valid_blocks_carried.get(event.creator()).is_none() {
            let valid_block_carried = {
                let payloads_made_valid = self
                    .peer_manager
                    .iter()
                    .flat_map(|(_peer, events)| {
                        events.iter().filter_map(|(_index, event_hash)| {
                            self.events
                                .get(event_hash)
                                .map(|event| event.vote().map(|vote| vote.payload()))
                        })
                    })
                    .filter_map(|this_payload| {
                        if self.peer_manager.is_super_majority(
                            self.n_ancestors_carrying_payload(event, &this_payload),
                        ) {
                            this_payload
                        } else {
                            None
                        }
                    });
                payloads_made_valid.max().map(|max_payload_made_valid| {
                    (
                        event.creator().clone(),
                        (*event.hash(), max_payload_made_valid.clone()),
                    )
                })
            };
            if let Some((peer, event_with_valid_block)) = valid_block_carried {
                let _ = event
                    .valid_blocks_carried
                    .insert(peer, event_with_valid_block);
            }
        }
        Ok(())
    }

    fn n_ancestors_carrying_payload(
        &self,
        event: &Event<T, S::PublicId>,
        payload: &Option<&T>,
    ) -> usize {
        let payload_already_reached_consensus = self.consensus_history.iter().any(|payload_hash| {
            Some(*payload_hash) == payload.and_then(|payload| {
                let serialised = serialise(&payload).ok();
                serialised.map(|bytes| Hash::from(bytes.as_slice()))
            })
        });
        if payload_already_reached_consensus {
            return 0;
        }
        let my_payload = if event.vote().map(|vote| vote.payload()) == *payload {
            1
        } else {
            0
        };
        let my_ancestors_payload = self
            .peer_manager
            .iter()
            .filter(|(peer, events)| {
                events.iter().any(|(_index, event_hash)| {
                    let last_ancestor_index = &event.last_ancestors.get(peer);
                    match self.events.get(event_hash) {
                        Some(that_event) => {
                            (*payload == that_event.vote().map(|vote| vote.payload()))
                                && (last_ancestor_index.map_or(false, |last_index| {
                                    that_event
                                        .index
                                        .map_or(false, |that_index| *last_index >= that_index)
                                }))
                        }
                        None => false,
                    }
                })
            })
            .count();
        my_payload + my_ancestors_payload
    }

    fn set_observations(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let observations = {
            let event = self.events.get(event_hash).ok_or(Error::Logic)?;
            event
                .valid_blocks_carried
                .iter()
                .filter_map(|(peer, (old_hash, _payload))| {
                    let old_event = self.events.get(old_hash)?;
                    if self.does_strongly_see(event, old_event) {
                        Some(peer)
                    } else {
                        None
                    }
                })
                .cloned()
                .collect()
        };
        self.events
            .get_mut(event_hash)
            .map(|ref mut event| event.observations = observations)
            .ok_or(Error::Logic)
    }

    fn set_meta_votes(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let total_peers = self.peer_manager.iter().count();
        let mut meta_votes = BTreeMap::new();
        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        let event = self.events.get(event_hash).ok_or(Error::Logic)?;
        if let Some(parent_votes) = self
            .self_parent(event)
            .and_then(|parent| self.meta_votes.get(parent.hash()).cloned())
        {
            for (peer_id, parent_event_votes) in parent_votes {
                let new_meta_votes = {
                    let other_votes = self.collect_other_meta_votes(&peer_id, event);
                    let coin_tosses = self.toss_coins(&peer_id, &parent_event_votes, event)?;
                    MetaVote::next(&parent_event_votes, &other_votes, &coin_tosses, total_peers)
                };
                let _ = meta_votes.insert(peer_id, new_meta_votes);
            }
        } else if self.is_observer(event) {
            // Start meta votes for this event.
            for peer_id in self.peer_manager.all_ids() {
                let other_votes = self.collect_other_meta_votes(peer_id, event);
                let initial_estimate = event.observations.contains(peer_id);
                let _ = meta_votes.insert(
                    peer_id.clone(),
                    MetaVote::new(initial_estimate, &other_votes, total_peers),
                );
            }
        };

        if !meta_votes.is_empty() {
            let _ = self.meta_votes.insert(*event_hash, meta_votes);
        }
        Ok(())
    }

    fn update_round_hashes(&mut self, event_hash: &Hash) -> Result<(), Error> {
        if let Some(meta_votes) = self.meta_votes.get(event_hash) {
            for (peer_id, event_votes) in meta_votes.iter() {
                for meta_vote in event_votes {
                    if let Some(hashes) = self.round_hashes.get_mut(&peer_id) {
                        while hashes.len() < meta_vote.round + 1 {
                            let next_round_hash = hashes[hashes.len() - 1].increment_round()?;
                            hashes.push(next_round_hash);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn toss_coins(
        &self,
        peer_id: &S::PublicId,
        parent_votes: &[MetaVote],
        event: &Event<T, S::PublicId>,
    ) -> Result<BTreeMap<usize, bool>, Error> {
        let mut coin_tosses = BTreeMap::new();
        for parent_vote in parent_votes {
            let _ = self
                .toss_coin(peer_id, parent_vote, event)?
                .map(|coin| coin_tosses.insert(parent_vote.round, coin));
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        peer_id: &S::PublicId,
        parent_vote: &MetaVote,
        event: &Event<T, S::PublicId>,
    ) -> Result<Option<bool>, Error> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            if parent_vote.round == 0 {
                // This should never happen as estimates get cleared only in increase step when the
                // step is Step::GenuineFlip and the round gets incremented
                return Err(Error::Logic);
            }
            parent_vote.round - 1
        } else if parent_vote.step == Step::GenuineFlip {
            parent_vote.round
        } else {
            return Ok(None);
        };
        let round_hash = if let Some(hashes) = self.round_hashes.get(peer_id) {
            hashes[round].value()
        } else {
            // Should be unreachable.
            return Err(Error::Logic);
        };

        // Get the gradient of leadership.
        let mut peer_id_hashes = self.peer_manager.peer_id_hashes().clone();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.0, &rhs.0));

        // Try to get the "most-leader"'s aux value.
        let creator = &peer_id_hashes[0].1;
        if let Some(creator_event_index) = event.last_ancestors.get(creator) {
            if let Some(aux_value) = self.aux_value(creator, *creator_event_index, peer_id, round) {
                return Ok(Some(aux_value));
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(round) {
            for (_, creator) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors.get(creator) {
                    if let Some(aux_value) =
                        self.aux_value(creator, *creator_event_index, peer_id, round)
                    {
                        return Ok(Some(aux_value));
                    }
                }
            }
        }

        Ok(None)
    }

    // Returns the aux value for the given peer, created by `creator`, at the given round and at
    // the genuine flip step.
    fn aux_value(
        &self,
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
    ) -> Option<bool> {
        self.meta_votes_since_round_and_step(
            creator,
            creator_event_index,
            peer_id,
            round,
            &Step::GenuineFlip,
        ).first()
            .and_then(|meta_vote| meta_vote.aux_value)
    }

    // Skips back through our events until we've passed `responsiveness_threshold` response events
    // and sees if we had our own `aux_value` set at this round and step.  If so, returns `true`.
    fn stop_waiting(&self, round: usize) -> bool {
        let mut event_hash = self
            .peer_manager
            .last_event_hash(self.peer_manager.our_id().public_id());
        let mut response_count = 0;
        loop {
            if let Some(evnt) = event_hash.and_then(|hash| self.events.get(hash)) {
                if evnt.is_response() {
                    response_count += 1;
                    if response_count == self.responsiveness_threshold {
                        break;
                    }
                }
                event_hash = evnt.self_parent();
            } else {
                return false;
            }
        }
        let hash = match event_hash {
            Some(hash) => hash,
            None => return false, // This should be unreachable.
        };
        self.meta_votes
            .get(&hash)
            .and_then(|meta_votes| meta_votes.get(self.peer_manager.our_id().public_id()))
            .map_or(false, |event_votes| {
                event_votes.iter().any(|meta_vote| {
                    meta_vote.round == round
                        && meta_vote.step == Step::GenuineFlip
                        && meta_vote.aux_value.is_some()
                })
            })
    }

    // Returns the meta votes for the given peer, created by `creator`, since the given round and
    // step.
    // Starts iterating down the creator's events starting from `creator_event_index`.
    fn meta_votes_since_round_and_step(
        &self,
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
        step: &Step,
    ) -> Vec<MetaVote> {
        if let Some(event_hash) = self
            .peer_manager
            .event_by_index(creator, creator_event_index)
        {
            if let Some(latest_votes) = self
                .meta_votes
                .get(event_hash)
                .and_then(|meta_votes| meta_votes.get(peer_id))
                .map(|meta_votes| {
                    meta_votes
                        .iter()
                        .filter(|meta_vote| {
                            meta_vote.round > round
                                || meta_vote.round == round && meta_vote.step >= *step
                        })
                        .cloned()
                        .collect()
                }) {
                latest_votes
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by `peer_id`.
    fn collect_other_meta_votes(
        &self,
        peer_id: &S::PublicId,
        event: &Event<T, S::PublicId>,
    ) -> Vec<Vec<MetaVote>> {
        let mut other_votes = vec![];
        for creator in self
            .peer_manager
            .all_ids()
            .iter()
            .filter(|&id| *id != event.creator())
        {
            if let Some(meta_votes) = event
                .last_ancestors
                .get(creator)
                .map(|creator_event_index| {
                    self.meta_votes_since_round_and_step(
                        creator,
                        *creator_event_index,
                        &peer_id,
                        0,
                        &Step::ForcedTrue,
                    )
                }) {
                other_votes.push(meta_votes)
            }
        }
        other_votes
    }

    fn next_stable_block(&mut self) -> Option<Block<T, S::PublicId>> {
        self.our_last_event_hash()
            .and_then(|hash| self.meta_votes.get(&hash))
            .and_then(|our_last_meta_votes| {
                let our_decided_meta_votes =
                    our_last_meta_votes.iter().filter_map(|(id, event_votes)| {
                        let vote = event_votes.last();
                        vote.and_then(|v| {
                            if v.decision.is_some() {
                                Some((id, v))
                            } else {
                                None
                            }
                        })
                    });
                if our_decided_meta_votes.clone().count() < self.peer_manager.all_ids().len() {
                    None
                } else {
                    let mut elected_valid_blocks = our_decided_meta_votes
                        .filter_map(|(id, vote)| {
                            if vote.decision == Some(true) {
                                self.our_last_event_hash()
                                    .and_then(|hash| self.events.get(&hash))
                                    .and_then(|last_event| last_event.valid_blocks_carried.get(&id))
                            } else {
                                None
                            }
                        })
                        .cloned()
                        .collect::<Vec<(Hash, T)>>();
                    // We sort the events by their payloads to avoid ties when picking the event
                    // with the most represented payload.
                    // Because `max` guarantees that "If several elements are equally
                    // maximum, the last element is returned.", this should be enough to break
                    // any tie.
                    elected_valid_blocks.sort_by(|(_, lhs_payload), (_, rhs_payload)| {
                        lhs_payload.cmp(&rhs_payload)
                    });
                    let payloads = elected_valid_blocks
                        .iter()
                        .map(|(_hash, payload)| payload)
                        .collect::<Vec<_>>();
                    let copied_payloads = payloads.clone();
                    copied_payloads
                        .iter()
                        .max_by(|lhs_payload, rhs_payload| {
                            let lhs_count = payloads
                                .iter()
                                .filter(|payload| lhs_payload == payload)
                                .count();
                            let rhs_count = payloads
                                .iter()
                                .filter(|payload| rhs_payload == payload)
                                .count();
                            lhs_count.cmp(&rhs_count)
                        })
                        .cloned()
                        .and_then(|winning_payload| {
                            let votes = self
                                .events
                                .iter()
                                .filter_map(|(_hash, event)| {
                                    event.vote().and_then(|vote| {
                                        if vote.payload() == winning_payload {
                                            Some((event.creator().clone(), vote.clone()))
                                        } else {
                                            None
                                        }
                                    })
                                })
                                .collect();
                            Block::new(winning_payload.clone(), &votes).ok()
                        })
                }
            })
    }

    fn clear_consensus_data(&mut self, payload: &T) -> Result<(), Error> {
        // Clear all leftover data from previous consensus
        self.round_hashes = BTreeMap::new();
        self.meta_votes = BTreeMap::new();
        self.events.iter_mut().for_each(|(_hash, event)| {
            event.observations = BTreeSet::new();
            let new_valid_blocks = event
                .valid_blocks_carried
                .clone()
                .into_iter()
                .filter(|(_peer, (_hash, this_payload))| payload != this_payload)
                .collect();

            event.valid_blocks_carried = new_valid_blocks;
        });

        let events = self.events.clone();
        for (event_hash, mut event) in events {
            self.set_valid_blocks_carried(&mut event)?;
            if let Some(evnt) = self.events.get_mut(&event_hash) {
                *evnt = event;
            } else {
                return Err(Error::Logic);
            }
        }
        Ok(())
    }

    fn restart_consensus(&mut self, latest_block_hash: &Hash) -> Result<(), Error> {
        self.round_hashes = self
            .peer_manager
            .all_ids()
            .iter()
            .filter_map(|peer| {
                let peer_id = *peer;
                RoundHash::new(*peer, *latest_block_hash)
                    .ok()
                    .map(|round_hash| (peer_id.clone(), vec![round_hash]))
            })
            .collect();
        let events_hashes = self
            .events_order
            .iter()
            // Start from the oldest event with a valid block considering all creators' events.
            .skip_while(|hash| {
                self.events.get(&hash).map_or(true, |event| event.valid_blocks_carried.is_empty())
            })
            .cloned()
            .collect::<Vec<_>>();
        for event_hash in &events_hashes {
            let _ = self.process_event(event_hash);
        }
        Ok(())
    }

    // Returns the number of peers through which there is a directed path in the gossip graph
    // between event X and event Y.
    fn n_peers_with_directed_paths(
        &self,
        x: &Event<T, S::PublicId>,
        y: &Event<T, S::PublicId>,
    ) -> usize {
        y.first_descendants
            .iter()
            .filter(|(peer_id, descendant)| {
                x.last_ancestors
                    .get(&peer_id)
                    .map(|last_ancestor| last_ancestor >= *descendant)
                    .unwrap_or(false)
            })
            .count()
    }

    // Returns whether event X can strongly see the event Y.
    fn does_strongly_see(&self, x: &Event<T, S::PublicId>, y: &Event<T, S::PublicId>) -> bool {
        self.peer_manager
            .is_super_majority(self.n_peers_with_directed_paths(x, y))
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

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.
    fn events_to_gossip_to_peer(
        &self,
        peer_id: &S::PublicId,
    ) -> Result<impl Iterator<Item = &Event<T, S::PublicId>>, Error> {
        let other_parent = {
            let other_parent_hash = self
                .peer_manager
                .last_event_hash(peer_id)
                .ok_or(Error::Logic)?;
            self.events.get(other_parent_hash).ok_or(Error::Logic)?
        };
        let mut last_ancestors_hashes = other_parent
            .last_ancestors
            .iter()
            .filter_map(|(id, &index)| self.peer_manager.event_by_index(id, index))
            .collect::<BTreeSet<_>>();
        // As `peer_id` isn't guaranteed to have `last_ancestor_hash` for all peers (which will
        // happen during the early stage when a node has not heard from all others), this may cause
        // the early events in `self.events_order` to be skipped mistakenly. To avoid this, if there
        // are any peers for which `peer_id` doesn't have a `last_ancestors` entry, add those peers'
        // oldest events we know about to the list of hashes.
        for (peer, events) in self.peer_manager.iter() {
            if !other_parent.last_ancestors.contains_key(peer) {
                if let Some(hash) = events.get(&0) {
                    let _ = last_ancestors_hashes.insert(hash);
                }
            }
        }
        Ok(self
            .events_order
            .iter()
            .skip_while(move |hash| !last_ancestors_hashes.contains(hash))
            .filter_map(move |hash| self.events.get(hash)))
    }
}

impl<T: NetworkEvent, S: SecretId> Debug for Parsec<T, S> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        dump_gossip_graph::<T, S>(f, &self.events, &self.meta_votes)
    }
}
