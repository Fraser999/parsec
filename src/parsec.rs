// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
// #[cfg(any(feature = "testing", all(test, feature = "mock")))]
// use dev_utils::ParsedContents;
use dump_graph;
use error::{Error, Result};
#[cfg(any(all(test, feature = "mock"), feature = "malice-detection"))]
use gossip::EventHash;
use gossip::{
    Event, EventContextMut, EventContextRef, EventIndex, Graph, IndexedEventRef, PackedEvent,
    Request, Response, UnpackedEvent,
};
#[cfg(feature = "malice-detection")]
use id::PublicId;
use id::SecretId;
use meta_voting::{MetaElectionHandle, MetaElections, MetaEvent, MetaEventBuilder, MetaVote, Step};
#[cfg(any(feature = "testing", all(test, feature = "mock")))]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
#[cfg(feature = "malice-detection")]
use observation::UnprovableMalice;
use observation::{
    is_more_than_two_thirds, ConsensusMode, Malice, Observation, ObservationHash, ObservationKey,
    ObservationStore,
};
use peer_list::{PeerList, PeerState};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::mem;
#[cfg(all(test, feature = "mock"))]
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::usize;

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused [Block](struct.Block.html)s by applying the PARSEC
/// algorithm. A `Block`'s payload, described by the [Observation](enum.Observation.html) type, is
/// called an "observation" or a "transaction".
///
/// The struct is generic with regards to two type arguments: one that represents a network event,
/// and one that represents a peer ID on the network. This allows the consumer to customise both
/// what constitutes a transaction that can get consensus, and the way peers are identified. The
/// types have to implement [NetworkEvent](trait.NetworkEvent.html) and
/// [SecretId](trait.SecretId.html) traits, respectively.
///
/// The `Parsec` struct exposes two constructors:
///
/// * [from_genesis](struct.Parsec.html#method.from_genesis), if the owning peer is a part of the
/// genesis group, i.e. the initial group of peers that participate in the network startup
/// * [from_existing](struct.Parsec.html#method.from_existing), if the owning peer is trying to
/// join an already functioning network
///
/// Once the peer becomes a full member of the section,
/// [gossip_recipients](struct.Parsec.html#method.gossip_recipients) will start to return potential
/// partners for gossip. In order to initiate gossip exchange with a partner,
/// [create_gossip](struct.Parsec.html#method.create_gossip) should be called.
///
/// Any messages of type [Request](struct.Request.html) or [Response](struct.Response.html)
/// received by the network layer should be passed to
/// [handle_request](struct.Parsec.html#method.handle_request) and
/// [handle_response](struct.Parsec.html#method.handle_response), respectively.
///
/// If the owning peer needs to propose something to be consensused, it has to call the
/// [vote_for](struct.Parsec.html#method.vote_for) method.
///
/// The [poll](struct.Parsec.html#method.poll) method is used to get the observations in the
/// consensused order.
///
/// Most public methods return an error if called after the owning peer has been removed from the
/// section, i.e. a block with payload `Observation::Remove(our_id)` has been made stable.
///
/// For more details, see the descriptions of methods below.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_list: PeerList<S>,
    // The Gossip graph.
    graph: Graph<S::PublicId>,
    // Information about observations stored in the graph, mapped to their hashes.
    observations: ObservationStore<T, S::PublicId>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    // The map of meta votes of the events on each consensus block.
    meta_elections: MetaElections,
    consensus_mode: ConsensusMode,
    // Accusations to raise at the end of the processing of current gossip message.
    pending_accusations: Accusations<T, S::PublicId>,
    // Accusations to raise at the end of the processing of current gossip message, once we've
    // established they are genuine.
    #[cfg(feature = "malice-detection")]
    candidate_accomplice_accusations: CandidateAccompliceAccusations<T, S::PublicId>,
    // Peers we accused of unprovable malice.
    #[cfg(feature = "malice-detection")]
    unprovable_offenders: HashSet<Rc<S::PublicId>>,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    ///
    /// * `our_id` is the value that will identify the owning peer in the network.
    /// * `genesis_group` is the set of public IDs of the peers that are present at the network
    /// startup.
    /// * `consensus_mode` determines how many votes are needed for an observation to become a
    /// candidate for consensus. For more details, see [ConsensusMode](enum.ConsensusMode.html)
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        if !genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group must contain us");
        }

        let mut peer_list = PeerList::new(our_id);
        let genesis_indices: PeerIndexSet = genesis_group
            .iter()
            .map(|peer_id| {
                if peer_id == peer_list.our_pub_id() {
                    let peer_index = PeerIndex::OUR;
                    peer_list.change_peer_state(peer_index, PeerState::active());
                    peer_index
                } else {
                    peer_list.add_peer(peer_id.clone(), PeerState::active())
                }
            })
            .collect();

        for peer_index in &genesis_indices {
            peer_list.initialise_peer_membership_list(*peer_index, genesis_indices.iter().cloned())
        }

        let mut parsec = Self::empty(peer_list, genesis_indices, consensus_mode);
        parsec
            .meta_elections
            .initialise_current_election(parsec.peer_list.all_ids());

        // Add initial event.
        let event = Event::new_initial(parsec.event_context());
        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        // Add event carrying genesis observation.
        let genesis_observation = Observation::Genesis(genesis_group.clone());
        let event = parsec.our_last_event_index().and_then(|self_parent| {
            Event::new_from_observation(
                self_parent,
                genesis_observation,
                parsec.event_context_mut(),
            )
        });
        if let Err(error) = event.and_then(|event| parsec.add_event(event)) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding the genesis observation: {:?}",
                parsec.our_pub_id(),
                error,
            );
        }

        parsec
    }

    /// Creates a new `Parsec` for a peer that is joining an existing section.
    ///
    /// * `our_id` is the value that will identify the owning peer in the network.
    /// * `genesis_group` is the set of public IDs of the peers that were present at the section
    /// startup.
    /// * `section` is the set of public IDs of the peers that constitute the section at the time
    /// of joining. They are the peers this `Parsec` instance will accept gossip from.
    /// * `consensus_mode` determines how many votes are needed for an observation to become a
    /// candidate for consensus. For more details, see [ConsensusMode](enum.ConsensusMode.html)
    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        if genesis_group.is_empty() {
            log_or_panic!("Genesis group can't be empty");
        }

        if genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group can't already contain us");
        }

        if section.is_empty() {
            log_or_panic!("Section can't be empty");
        }

        if section.contains(our_id.public_id()) {
            log_or_panic!("Section can't already contain us");
        }

        let mut peer_list = PeerList::new(our_id);

        // Add ourselves
        peer_list.change_peer_state(PeerIndex::OUR, PeerState::RECV);

        // Add the genesis group.
        let genesis_indices: PeerIndexSet = genesis_group
            .iter()
            .map(|peer_id| peer_list.add_peer(peer_id.clone(), PeerState::VOTE | PeerState::SEND))
            .collect();
        for peer_index in &genesis_indices {
            peer_list.initialise_peer_membership_list(*peer_index, genesis_indices.iter().cloned());
        }

        // Add the current section members.
        for peer_id in section {
            if peer_list.contains(peer_id) {
                continue;
            }
            let _ = peer_list.add_peer(peer_id.clone(), PeerState::SEND);
        }

        let mut parsec = Self::empty(peer_list, genesis_indices, consensus_mode);

        parsec
            .meta_elections
            .initialise_current_election(parsec.peer_list.all_ids());

        let initial_event = Event::new_initial(parsec.event_context());
        if let Err(error) = parsec.add_event(initial_event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        parsec
    }

    // Construct empty `Parsec` with no peers (except us) and no gossip events.
    fn empty(
        peer_list: PeerList<S>,
        genesis_group: PeerIndexSet,
        consensus_mode: ConsensusMode,
    ) -> Self {
        dump_graph::init();

        Self {
            peer_list,
            graph: Graph::new(),
            consensused_blocks: VecDeque::new(),
            observations: BTreeMap::new(),
            meta_elections: MetaElections::new(genesis_group),
            consensus_mode,
            pending_accusations: vec![],
            #[cfg(feature = "malice-detection")]
            candidate_accomplice_accusations: BTreeSet::new(),
            #[cfg(feature = "malice-detection")]
            unprovable_offenders: PeerIndexSet::default(),
        }
    }

    /// Returns our public ID
    pub fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_pub_id()
    }

    /// Inserts the owning peer's vote for `observation` into the gossip graph. The subsequent
    /// gossip messages will spread the vote to other peers, eventually making it a candidate for
    /// the next consensused block.
    ///
    /// Returns an error if the owning peer is not a full member of the section yet, if it has
    /// already voted for this `observation`, or if adding a gossip event containing the vote to
    /// the gossip graph failed.
    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<()> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.confirm_self_state(PeerState::VOTE)?;

        if self.have_voted_for(&observation) {
            return Err(Error::DuplicateVote);
        }

        let self_parent = self.our_last_event_index()?;
        let event =
            Event::new_from_observation(self_parent, observation, self.event_context_mut())?;

        let _ = self.add_event(event)?;
        Ok(())
    }

    /// Returns an iterator with the IDs of peers who the owning peer can send gossip messages to.
    /// Calling `create_gossip` with a peer ID returned by this method is guaranteed to succeed
    /// (assuming no section mutation happened in between).
    pub fn gossip_recipients(&self) -> impl Iterator<Item = &S::PublicId> {
        self.peer_list
            .gossip_recipients()
            .map(|(_, peer)| peer.id())
    }

    /// Creates a new message to be gossipped to a peer, containing all gossip events this peer
    /// thinks that peer needs. If `peer_id` is `None`, a message containing all known gossip
    /// events is returned. If `peer_id` is `Some` and the given peer is not an active node, an
    /// error is returned.
    ///
    /// * `peer_id`: the intended recipient of the gossip message
    /// * returns a `Request` to be sent to the intended recipient
    pub fn create_gossip(&self, peer_id: Option<&S::PublicId>) -> Result<Request<T, S::PublicId>> {
        self.confirm_self_state(PeerState::SEND)?;

        if let Some(peer_id) = peer_id {
            let peer_index = self.get_peer_index(peer_id)?;
            // We require `PeerState::VOTE` in addition to `PeerState::RECV` here, because if the
            // peer does not have `PeerState::VOTE`, it means we haven't yet reached consensus on
            // adding them to the section so we shouldn't contact them yet.
            self.confirm_peer_state(peer_index, PeerState::VOTE | PeerState::RECV)?;

            if self.peer_list.last_event(peer_index).is_some() {
                debug!(
                    "{:?} creating gossip request for {:?}",
                    self.our_pub_id(),
                    peer_id
                );

                let events = self.events_to_gossip_to_peer(peer_index)?;
                return self.pack_events(events).map(Request::new);
            }
        }

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        self.pack_events(self.graph.iter().map(|e| e.inner()))
            .map(Request::new)
    }

    /// Handles a `Request` the owning peer received from the `src` peer.  Returns a `Response` to
    /// be sent back to `src`, or `Err` if the request was not valid or if `src` has been removed
    /// from the section already.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>> {
        debug!(
            "{:?} received gossip request from {:?}",
            self.our_pub_id(),
            src
        );
        let src_index = self.get_peer_index(src)?;

        let other_parent = req.hash_of_last_event_created_by(src)?;
        let other_parent = other_parent.and_then(|hash| self.graph.get_index(&hash));

        let forking_peers = self.unpack_and_add_events(src_index, req.packed_events)?;
        self.create_sync_event(src_index, true, &forking_peers, other_parent)?;
        self.create_accusation_events()?;

        let events = self.events_to_gossip_to_peer(src_index)?;
        self.pack_events(events).map(Response::new)
    }

    /// Handles a `Response` the owning peer received from the `src` peer. Returns `Err` if the
    /// response was not valid or if `src` has been removed from the section already.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<()> {
        debug!(
            "{:?} received gossip response from {:?}",
            self.our_pub_id(),
            src
        );
        let src_index = self.get_peer_index(src)?;

        let other_parent = resp.hash_of_last_event_created_by(src)?;
        let other_parent = other_parent.and_then(|hash| self.graph.get_index(&hash));

        let forking_peers = self.unpack_and_add_events(src_index, resp.packed_events)?;
        self.create_sync_event(src_index, false, &forking_peers, other_parent)?;
        self.create_accusation_events()
    }

    /// Returns the next stable block, if any. The method might need to be called more than once
    /// for the caller to get all the blocks that have been consensused. A `None` value means that
    /// all the blocks consensused so far have already been returned.
    ///
    /// Once the owning peer has been removed from the section (i.e. a block with payload
    /// `Observation::Remove(our_id)` has been made stable), then no further blocks will be
    /// enqueued. So, once `poll()` returns such a block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Check if the owning peer can vote (that is, it has reached a consensus on itself being a
    /// full member of the section).
    pub fn can_vote(&self) -> bool {
        self.peer_list.our_state().can_vote()
    }

    /// Checks if the given `observation` has already been voted for by the owning peer.
    pub fn have_voted_for(&self, observation: &Observation<T, S::PublicId>) -> bool {
        let hash = ObservationHash::from(observation);
        let key = ObservationKey::new(hash, PeerIndex::OUR, self.consensus_mode.of(observation));
        self.observations
            .get(&key)
            .map(|info| info.created_by_us)
            .unwrap_or(false)
    }

    /// Check if there are any observations that have been voted for but not yet consensused - i.e.
    /// if there is a gossip event containing a vote for a payload that is not yet a part of a
    /// stable block.
    pub fn has_unconsensused_observations(&self) -> bool {
        self.observations.values().any(|info| !info.consensused)
    }

    /// Returns observations voted for by the owning peer which haven't been returned as a stable
    /// block by `poll` yet.
    /// This includes observations that are either not yet consensused or that are already
    /// consensused, but not yet popped out of the consensus queue.
    ///
    /// The observations are sorted first by the consensus order, then by the vote order.
    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.our_consensused_observations()
            .chain(self.our_unconsensused_observations())
    }

    fn our_consensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations.values().filter_map(move |info| {
            if info.created_by_us
                && info.consensused
                && self
                    .consensused_blocks
                    .iter()
                    .any(|block| block.payload() == &info.observation)
            {
                Some(&info.observation)
            } else {
                None
            }
        })
    }

    fn our_unconsensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations.values().filter_map(|info| {
            if info.created_by_us && !info.consensused {
                Some(&info.observation)
            } else {
                None
            }
        })
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event(&self, event_index: EventIndex) -> Result<IndexedEventRef<S::PublicId>> {
        self.graph.get(event_index).ok_or_else(|| {
            log_or_panic!(
                "{:?} doesn't have event {:?}",
                self.our_pub_id(),
                event_index
            );
            Error::Logic
        })
    }

    fn confirm_peer_state(&self, peer_index: PeerIndex, required: PeerState) -> Result<()> {
        let actual = self.peer_list.peer_state(peer_index);
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} detected invalid state of {:?} (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                peer_index,
                required,
                actual,
            );
            Err(Error::InvalidPeerState { required, actual })
        }
    }

    fn confirm_self_state(&self, required: PeerState) -> Result<()> {
        let actual = self.peer_list.our_state();
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} has invalid state (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                required,
                actual,
            );
            Err(Error::InvalidSelfState { required, actual })
        }
    }

    fn get_peer_index(&self, peer_id: &S::PublicId) -> Result<PeerIndex> {
        self.peer_list.get_index(peer_id).ok_or(Error::UnknownPeer)
    }

    fn our_last_event_index(&self) -> Result<EventIndex> {
        self.peer_list.last_event(PeerIndex::OUR).ok_or_else(|| {
            log_or_panic!(
                "{:?} has no last event.\n{:?}\n",
                self.our_pub_id(),
                self.peer_list
            );
            Error::Logic
        })
    }

    fn is_observer(&self, builder: &MetaEventBuilder<S::PublicId>) -> bool {
        // An event is an observer if it has a supermajority of observees and its self-parent
        // does not.
        let voter_count = self.voter_count(builder.election());

        if !is_more_than_two_thirds(builder.observee_count(), voter_count) {
            return false;
        }

        let self_parent_index = if let Some(index) = builder.event().self_parent() {
            index
        } else {
            log_or_panic!(
                "{:?} has event {:?} with observations, but not self-parent",
                self.our_pub_id(),
                *builder.event()
            );
            return false;
        };

        let self_parent = if let Ok(event) = self.get_known_event(self_parent_index) {
            event
        } else {
            return false;
        };

        // If self-parent is initial, we don't have to check it's meta-event, as we already know it
        // can not have any observations. Also, we don't assign meta-events to initial events anyway.
        if self_parent.is_initial() {
            return true;
        }

        // If self-parent is earlier in history than the start of the meta-election, it won't have
        // a meta-event; but it also means that it wasn't an observer, so this event is
        if self.start_index(builder.election()) > self_parent.topological_index() {
            return true;
        }

        if let Some(meta_parent) = self
            .meta_elections
            .meta_event(builder.election(), self_parent_index)
        {
            !is_more_than_two_thirds(meta_parent.observees.len(), voter_count)
        } else {
            log_or_panic!(
                "{:?} doesn't have meta-event for event {:?} (self-parent of {:?}) in meta-election {:?}",
                self.our_pub_id(),
                *self_parent,
                builder.event().hash(),
                builder.election(),
            );

            false
        }
    }

    fn pack_events<'a, I>(&self, events: I) -> Result<Vec<PackedEvent<T, S::PublicId>>>
    where
        I: IntoIterator<Item = &'a Event<S::PublicId>>,
        S::PublicId: 'a,
    {
        events
            .into_iter()
            .map(|event| event.pack(self.event_context()))
            .collect()
    }

    fn unpack_and_add_events(
        &mut self,
        src_index: PeerIndex,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<PeerIndexSet> {
        self.confirm_self_state(PeerState::RECV)?;
        self.confirm_peer_state(src_index, PeerState::SEND)?;

        let mut forking_peers = PeerIndexSet::default();
        let mut known = Vec::new();

        // Among the packed_events, Keep track of each peer's earliest events' self_parent, as we
        // will use them as bounds in the graph for where we look for malice accusations.
        // NOTE: there is the assumption here that the events arrive in order.
        #[cfg(feature = "malice-detection")]
        let first_event_by_peer_in_packed_event =
            collect_first_self_parents::<T, S>(&packed_events);

        for packed_event in packed_events {
            match Event::unpack(packed_event, &forking_peers, self.event_context_mut())? {
                UnpackedEvent::New(event) => {
                    if self
                        .peer_list
                        .events_by_index(event.creator(), event.index_by_creator())
                        .next()
                        .is_some()
                    {
                        let _ = forking_peers.insert(event.creator());
                    }

                    let event_creator = event.creator();
                    let event_index = self.add_event(event)?;

                    // We have received an event of a peer in the message. The peer can now receive
                    // gossips from us as well.
                    self.peer_list
                        .change_peer_state(event_creator, PeerState::RECV);
                    self.peer_list
                        .record_gossiped_event_by(src_index, event_index);

                    #[cfg(feature = "malice-detection")]
                    {
                        // See if this event now allows us to act on any of the accusations in
                        // candidate_accomplice_accusations
                        self.act_on_accomplice_accusation_candidates_we_can_now_prove(event_index)?;
                        // We never act on accomplice immediately when we spot it as we need
                        // follow up events to be certain.
                        self.detect_accomplice(event_index, &first_event_by_peer_in_packed_event)?;
                    }
                }
                UnpackedEvent::Known(index) => {
                    known.push(index);
                }
            }
        }

        #[cfg(feature = "malice-detection")]
        {
            self.detect_premature_gossip()?;

            for event_index in known {
                self.detect_spam(src_index, event_index);
            }
        }

        Ok(forking_peers)
    }

    fn add_event(&mut self, event: Event<S::PublicId>) -> Result<EventIndex> {
        let our = event.creator() == PeerIndex::OUR;
        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_before_process(&event)?;
        }

        self.peer_list.confirm_can_add_event(&event)?;

        let has_unconsensused_payload = if let Some(info) = event
            .payload_key()
            .and_then(|key| self.observations.get_mut(key))
        {
            if our {
                info.created_by_us = true;
            }
            !info.consensused
        } else {
            false
        };

        let is_initial = event.is_initial();
        let event_index = {
            let event = self.graph.insert(event);
            self.peer_list.add_event(event);
            event.event_index()
        };

        if has_unconsensused_payload {
            self.meta_elections.add_unconsensused_event(event_index);
        }

        if is_initial {
            return Ok(event_index);
        }

        self.initialise_membership_list(event_index);
        self.process_events(event_index.topological_index())?;

        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_after_process(event_index);
        }

        Ok(event_index)
    }

    fn process_events(&mut self, mut start_index: usize) -> Result<()> {
        'outer: loop {
            for event_index in self.graph.indices_from(start_index) {
                match self.process_event(event_index)? {
                    PostProcessAction::Restart(new_start_index)
                        if new_start_index <= event_index.topological_index() =>
                    {
                        start_index = new_start_index;
                        continue 'outer;
                    }
                    PostProcessAction::Restart(_) | PostProcessAction::Continue => (),
                }
            }

            break;
        }

        Ok(())
    }

    fn process_event(&mut self, event_index: EventIndex) -> Result<PostProcessAction> {
        if self.peer_list.our_state() == PeerState::inactive() {
            return Ok(PostProcessAction::Continue);
        }

        let elections: Vec<_> = self.meta_elections.all().collect();
        for election in elections {
            self.create_meta_event(election, event_index)?;
        }

        let creator = self.get_known_event(event_index)?.creator();

        if let Some(payload_key) = self.compute_consensus(MetaElectionHandle::CURRENT, event_index)
        {
            self.output_consensus_info(&payload_key);

            match self.create_block(&payload_key) {
                Ok(block) => self.consensused_blocks.push_back(block),
                Err(Error::MissingVotes) => (),
                Err(error) => return Err(error),
            }

            self.mark_observation_as_consensused(&payload_key);

            self.handle_self_consensus(&payload_key);
            if creator != PeerIndex::OUR {
                self.handle_peer_consensus(creator, &payload_key);
            }

            // Calculate new unconsensused events here, because `MetaElections` doesn't have access
            // to the actual payloads, so can't tell which ones are consensused.
            let unconsensused_events = self.collect_unconsensused_events(&payload_key);
            let prev_election = self.meta_elections.new_election(
                payload_key,
                self.peer_list.voter_indices().collect(),
                unconsensused_events,
            );

            self.meta_elections
                .mark_as_decided(prev_election, PeerIndex::OUR);
            self.meta_elections.mark_as_decided(prev_election, creator);

            // Trigger reprocess.
            self.meta_elections
                .initialise_current_election(self.peer_list.all_ids());
            let start_index = self.start_index(MetaElectionHandle::CURRENT);
            return Ok(PostProcessAction::Restart(start_index));
        } else if creator != PeerIndex::OUR {
            let undecided: Vec<_> = self.meta_elections.undecided_by(creator).collect();
            for election in undecided {
                if let Some(payload_key) = self.compute_consensus(election, event_index) {
                    self.meta_elections.mark_as_decided(election, creator);
                    self.handle_peer_consensus(creator, &payload_key);
                }
            }
        }

        Ok(PostProcessAction::Continue)
    }

    fn output_consensus_info(&self, payload_key: &ObservationKey) {
        dump_graph::to_file(
            self.our_pub_id(),
            &self.graph,
            &self.meta_elections,
            &self.peer_list,
            &self.observations,
        );

        let payload = self
            .observations
            .get(payload_key)
            .map(|info| &info.observation);
        info!(
            "{:?} got consensus on block {} with payload {:?} and payload hash {:?}",
            self.our_pub_id(),
            self.meta_elections.consensus_history().len() - 1,
            payload,
            payload_key.hash()
        )
    }

    fn mark_observation_as_consensused(&mut self, payload_key: &ObservationKey) {
        if let Some(info) = self.observations.get_mut(payload_key) {
            info.consensused = true;
        } else {
            log_or_panic!(
                "{:?} doesn't know about observation with hash {:?}",
                self.peer_list.our_pub_id(),
                payload_key.hash()
            );
        }
    }

    /// Handles consensus reached by us.
    fn handle_self_consensus(&mut self, payload_key: &ObservationKey) {
        match self
            .observations
            .get(payload_key)
            .map(|info| info.observation.clone())
        {
            Some(Observation::Add { ref peer_id, .. }) => self.handle_add_peer(peer_id),
            Some(Observation::Remove { ref peer_id, .. }) => self.handle_remove_peer(peer_id),
            Some(Observation::Accusation {
                ref offender,
                ref malice,
            }) => {
                info!(
                    "{:?} removing {:?} due to consensus on accusation of malice {:?}",
                    self.our_pub_id(),
                    offender,
                    malice
                );

                self.handle_remove_peer(offender)
            }
            Some(Observation::Genesis(_)) | Some(Observation::OpaquePayload(_)) => (),
            None => {
                log_or_panic!("Failed to get observation from hash.");
            }
        }
    }

    fn handle_add_peer(&mut self, peer_id: &S::PublicId) {
        // - If we are already full member of the section, we can start sending gossips to
        //   the new peer from this moment.
        // - If we are the new peer, we must wait for the other members to send gossips to
        //   us first.
        //
        // To distinguish between the two, we check whether everyone we reached consensus on
        // adding also reached consensus on adding us.
        let recv = self
            .peer_list
            .iter()
            .filter(|(peer_index, peer)| {
                // Peers that can vote, which means we got consensus on adding them.
                peer.state().can_vote() &&
                        // Excluding us.
                        *peer_index != PeerIndex::OUR &&
                        // Excluding the peer being added.
                        peer.id() != peer_id
            })
            .all(|(_, peer)| {
                // Peers that can receive, which implies they've already sent us at least
                // one message which implies they've already reached consensus on adding us.
                peer.state().can_recv()
            });

        let state = if recv {
            PeerState::VOTE | PeerState::SEND | PeerState::RECV
        } else {
            PeerState::VOTE | PeerState::SEND
        };

        if let Some(peer_index) = self.peer_list.get_index(peer_id) {
            self.peer_list.change_peer_state(peer_index, state);
        } else {
            let _ = self.peer_list.add_peer(peer_id.clone(), state);
        }
    }

    fn handle_remove_peer(&mut self, peer_id: &S::PublicId) {
        if let Some(peer_index) = self.peer_list.get_index(peer_id) {
            self.peer_list.remove_peer(peer_index);
            self.meta_elections.handle_peer_removed(peer_index);
        }
    }

    // Handle consensus reached by other peer.
    fn handle_peer_consensus(&mut self, peer_index: PeerIndex, payload_key: &ObservationKey) {
        let payload = self
            .observations
            .get(payload_key)
            .map(|info| info.observation.clone());
        trace!(
            "{:?} detected that {:?} reached consensus on {:?}",
            self.our_pub_id(),
            peer_index,
            payload
        );

        match payload {
            Some(Observation::Add {
                peer_id: ref other_peer_id,
                ..
            }) => self
                .peer_list
                .add_to_peer_membership_list(peer_index, other_peer_id),
            Some(Observation::Remove {
                peer_id: ref other_peer_id,
                ..
            }) => self
                .peer_list
                .remove_from_peer_membership_list(peer_index, other_peer_id),
            Some(Observation::Accusation { ref offender, .. }) => self
                .peer_list
                .remove_from_peer_membership_list(peer_index, offender),
            _ => (),
        }
    }

    fn create_meta_event(
        &mut self,
        election: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Result<()> {
        if self
            .meta_elections
            .meta_event(election, event_index)
            .is_some()
        {
            return Ok(());
        }

        let (meta_event, creator) = {
            let event = self.get_known_event(event_index)?;
            trace!(
                "{:?} creating a meta-event in meta-election {:?} for event {:?}",
                self.our_pub_id(),
                election,
                event
            );

            let mut builder = MetaEvent::build(election, event);

            self.set_interesting_content(&mut builder);
            self.set_observees(&mut builder);
            self.set_meta_votes(&mut builder)?;

            (builder.finish(), event.creator())
        };

        self.meta_elections
            .add_meta_event(election, event_index, creator, meta_event);

        Ok(())
    }

    // Any payloads which this event sees as "interesting".  If this returns a non-empty set, then
    // this event is classed as an interesting one.
    fn set_interesting_content(&self, builder: &mut MetaEventBuilder<S::PublicId>) {
        if let Some(payloads_keys) =
            self.previous_interesting_content(builder.election(), builder.event())
        {
            builder.set_interesting_content(payloads_keys);
            return;
        };

        let peers_that_can_vote = self.voters(builder.election());
        let start_index = self.start_index(builder.election());

        let mut payloads: Vec<_> = self
            .unconsensused_events(builder.election())
            .map(|event| event.inner())
            .filter_map(|event| event.payload_key().map(|key| (event, key)))
            .filter(|(_, payload_key)| {
                !self.meta_elections.is_already_interesting_content(
                    builder.election(),
                    builder.event().creator(),
                    payload_key,
                )
            })
            .filter(|(event, payload_key)| {
                self.is_interesting_payload(builder, &peers_that_can_vote, payload_key)
                    || event.sees_fork()
                        && self.has_interesting_ancestor(builder, payload_key, start_index)
            })
            .map(|(event, payload_key)| {
                (
                    if event.creator() == builder.event().creator() {
                        event.index_by_creator()
                    } else {
                        usize::MAX
                    },
                    payload_key,
                )
            })
            .collect();

        // First, remove duplicates (preferring payloads voted for by the creator)...
        payloads
            .sort_by(|(l_index, l_key), (r_index, r_key)| (l_key, l_index).cmp(&(r_key, r_index)));
        payloads.dedup_by(|(_, l_key), (_, r_key)| l_key == r_key);

        // ...then sort the payloads in the order the creator voted for them, followed by the ones
        // not voted for by the creator (if any).
        payloads.sort();

        let payloads = payloads.into_iter().map(|(_, key)| key).cloned().collect();
        builder.set_interesting_content(payloads);
    }

    // Try to get interesting content of the given event from the previous meta-election.
    fn previous_interesting_content(
        &self,
        election: MetaElectionHandle,
        event: IndexedEventRef<S::PublicId>,
    ) -> Option<Vec<ObservationKey>> {
        let prev_election = self.meta_elections.preceding(election)?;

        // If membership change occurred, we can't reuse the interesting content.
        // Note: it's not enough to compare just the voter counts, because the preceding
        // meta-election might not necessarily be the directly preceding one, but might be further
        // in the past.
        if self.meta_elections.voters(election) != self.meta_elections.voters(prev_election) {
            return None;
        }

        let prev_meta_event = self
            .meta_elections
            .meta_event(prev_election, event.event_index())?;
        let payloads: Vec<_> = prev_meta_event
            .interesting_content
            .iter()
            .filter(|payload_key| {
                if self.meta_elections.is_already_interesting_content(
                    election,
                    event.creator(),
                    payload_key,
                ) {
                    return false;
                }

                if self
                    .meta_elections
                    .is_already_consensused(election, payload_key)
                {
                    return false;
                }

                true
            })
            .cloned()
            .collect();

        Some(payloads)
    }

    // Returns true if `builder.event()` has an ancestor by a different creator that has `payload`
    // in interesting content
    fn has_interesting_ancestor(
        &self,
        builder: &MetaEventBuilder<S::PublicId>,
        payload_key: &ObservationKey,
        start_index: usize,
    ) -> bool {
        self.graph
            .ancestors(builder.event())
            .take_while(|that_event| that_event.topological_index() >= start_index)
            .filter(|that_event| that_event.creator() != builder.event().creator())
            .any(|that_event| {
                self.meta_elections
                    .meta_event(builder.election(), that_event.event_index())
                    .map(|meta_event| meta_event.interesting_content.contains(payload_key))
                    .unwrap_or(false)
            })
    }

    // Returns true if enough of `valid_voters` have voted for the indicated payload from the
    // perspective of `builder.event()`.
    fn is_interesting_payload(
        &self,
        builder: &MetaEventBuilder<S::PublicId>,
        peers_that_can_vote: &PeerIndexSet,
        payload_key: &ObservationKey,
    ) -> bool {
        let num_peers_that_did_vote = self.num_creators_of_ancestors_carrying_payload(
            builder.election(),
            peers_that_can_vote,
            &*builder.event(),
            payload_key,
        );

        match payload_key.consensus_mode() {
            ConsensusMode::Single => {
                let num_ancestor_peers =
                    self.num_creators_of_ancestors(peers_that_can_vote, &*builder.event());
                is_more_than_two_thirds(num_ancestor_peers, peers_that_can_vote.len())
                    && num_peers_that_did_vote > 0
            }
            ConsensusMode::Supermajority => {
                is_more_than_two_thirds(num_peers_that_did_vote, peers_that_can_vote.len())
            }
        }
    }

    // Number of unique peers that created at least one ancestor of the given event.
    fn num_creators_of_ancestors(
        &self,
        peers_that_can_vote: &PeerIndexSet,
        event: &Event<S::PublicId>,
    ) -> usize {
        event
            .last_ancestors()
            .keys()
            .filter(|peer_index| peers_that_can_vote.contains(peer_index))
            .count()
    }

    // Number of unique peers that created at least one ancestor of the given event that carries the
    // given payload.
    fn num_creators_of_ancestors_carrying_payload(
        &self,
        election: MetaElectionHandle,
        peers_that_can_vote: &PeerIndexSet,
        event: &Event<S::PublicId>,
        payload_key: &ObservationKey,
    ) -> usize {
        peers_that_can_vote
            .iter()
            .filter(|peer_index| {
                self.unconsensused_events(election)
                    .map(|that_event| that_event.inner())
                    .filter(|that_event| that_event.creator() == **peer_index)
                    .filter_map(|that_event| that_event.payload_key().map(|key| (that_event, key)))
                    .any(|(that_event, that_payload_key)| {
                        payload_key == that_payload_key && event.sees(that_event)
                    })
            })
            .count()
    }

    fn set_observees(&self, builder: &mut MetaEventBuilder<S::PublicId>) {
        let observees = self
            .meta_elections
            .interesting_events(builder.election())
            .filter_map(|(peer_index, event_indices)| {
                let event_index = event_indices.front()?;
                let event = self.get_known_event(*event_index).ok()?;
                if self.strongly_sees(builder.election(), builder.event(), event) {
                    Some(peer_index)
                } else {
                    None
                }
            })
            .collect();
        builder.set_observees(observees);
    }

    fn set_meta_votes(&self, builder: &mut MetaEventBuilder<S::PublicId>) -> Result<()> {
        let voters = self.voters(builder.election());

        let parent_meta_votes = builder
            .event()
            .self_parent()
            .and_then(|parent_hash| {
                self.meta_elections
                    .meta_votes(builder.election(), parent_hash)
            })
            .and_then(|parent_meta_votes| {
                if !parent_meta_votes.is_empty() {
                    Some(parent_meta_votes)
                } else {
                    None
                }
            });

        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        if let Some(parent_meta_votes) = parent_meta_votes {
            for (peer_index, parent_event_votes) in parent_meta_votes {
                let new_meta_votes = {
                    let other_votes = self.collect_other_meta_votes(
                        builder.election(),
                        &voters,
                        *peer_index,
                        &*builder.event(),
                    );
                    let coin_tosses = self.toss_coins(
                        builder.election(),
                        &voters,
                        *peer_index,
                        &parent_event_votes,
                        builder.event(),
                    )?;
                    MetaVote::next(
                        &parent_event_votes,
                        &other_votes,
                        &coin_tosses,
                        voters.len(),
                    )
                };

                builder.add_meta_votes(*peer_index, new_meta_votes);
            }
        } else if self.is_observer(builder) {
            // Start meta votes for this event.
            for peer_index in &voters {
                let other_votes = self.collect_other_meta_votes(
                    builder.election(),
                    &voters,
                    *peer_index,
                    &*builder.event(),
                );
                let initial_estimate = builder.has_observee(*peer_index);

                builder.add_meta_votes(
                    *peer_index,
                    MetaVote::new(initial_estimate, &other_votes, voters.len()),
                );
            }
        };

        trace!(
            "{:?} has set the meta votes for {:?} in meta-election {:?}",
            self.our_pub_id(),
            *builder.event(),
            builder.election(),
        );

        Ok(())
    }

    fn toss_coins(
        &self,
        election: MetaElectionHandle,
        voters: &PeerIndexSet,
        peer_index: PeerIndex,
        parent_votes: &[MetaVote],
        event: IndexedEventRef<S::PublicId>,
    ) -> Result<BTreeMap<usize, bool>> {
        let mut coin_tosses = BTreeMap::new();
        for parent_vote in parent_votes {
            let _ = self
                .toss_coin(election, voters, peer_index, parent_vote, event)?
                .map(|coin| coin_tosses.insert(parent_vote.round, coin));
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        election: MetaElectionHandle,
        voters: &PeerIndexSet,
        peer_index: PeerIndex,
        parent_vote: &MetaVote,
        event: IndexedEventRef<S::PublicId>,
    ) -> Result<Option<bool>> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            if parent_vote.round == 0 {
                // This should never happen as estimates get cleared only in increase step when the
                // step is Step::GenuineFlip and the round gets incremented.
                log_or_panic!(
                    "{:?} missing parent vote estimates at round 0.",
                    self.our_pub_id()
                );
                return Err(Error::Logic);
            }
            parent_vote.round - 1
        } else if parent_vote.step == Step::GenuineFlip {
            parent_vote.round
        } else {
            return Ok(None);
        };
        let round_hash =
            if let Some(hashes) = self.meta_elections.round_hashes(election, peer_index) {
                hashes[round].value()
            } else {
                log_or_panic!("{:?} missing round hash.", self.our_pub_id());
                return Err(Error::Logic);
            };

        // Get the gradient of leadership.
        let mut peer_id_hashes: Vec<_> = self
            .peer_list
            .all_id_hashes()
            .filter(|(peer_index, _)| voters.contains(peer_index))
            .collect();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.1, &rhs.1));

        // Try to get the "most-leader"'s aux value.
        let creator = peer_id_hashes[0].0;
        if let Some(creator_event_index) = event.last_ancestors().get(&creator) {
            if let Some(aux_value) =
                self.aux_value(election, creator, *creator_event_index, peer_index, round)
            {
                return Ok(Some(aux_value));
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(election, round, event) {
            for (creator, _) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors().get(creator) {
                    if let Some(aux_value) =
                        self.aux_value(election, *creator, *creator_event_index, peer_index, round)
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
        election: MetaElectionHandle,
        creator: PeerIndex,
        creator_event_index: usize,
        peer_index: PeerIndex,
        round: usize,
    ) -> Option<bool> {
        self.meta_votes_since_round_and_step(
            election,
            creator,
            creator_event_index,
            peer_index,
            round,
            Step::GenuineFlip,
        )
        .next()
        .and_then(|meta_vote| meta_vote.aux_value)
    }

    // Skips back through events created by the peer until passed `responsiveness_threshold`
    // response events and sees if the peer had its `aux_value` set at this round.  If so, returns
    // `true`.
    fn stop_waiting(
        &self,
        election: MetaElectionHandle,
        round: usize,
        event: IndexedEventRef<S::PublicId>,
    ) -> bool {
        let mut event_index = Some(event.event_index());
        let mut response_count = 0;
        let responsiveness_threshold = self.responsiveness_threshold(election);

        loop {
            if let Some(event) = event_index.and_then(|index| self.get_known_event(index).ok()) {
                if event.is_response() {
                    response_count += 1;
                    if response_count == responsiveness_threshold {
                        break;
                    }
                }
                event_index = event.self_parent();
            } else {
                return false;
            }
        }
        let event_index = match event_index {
            Some(index) => index,
            None => {
                log_or_panic!("{:?} event_index was None.", self.our_pub_id());
                return false;
            }
        };
        self.meta_elections
            .meta_votes(election, event_index)
            .and_then(|meta_votes| meta_votes.get(&event.creator()))
            .map_or(false, |event_votes| {
                event_votes
                    .iter()
                    .any(|meta_vote| meta_vote.round == round && meta_vote.aux_value.is_some())
            })
    }

    // Returns the meta votes for the given peer, created by `creator`, since the given round and
    // step.  Starts iterating down the creator's events starting from `creator_event_index`.
    fn meta_votes_since_round_and_step(
        &self,
        election: MetaElectionHandle,
        creator: PeerIndex,
        creator_event_index: usize,
        peer_index: PeerIndex,
        round: usize,
        step: Step,
    ) -> impl Iterator<Item = &MetaVote> {
        let mut events = self.peer_list.events_by_index(creator, creator_event_index);
        let event = events.next().and_then(|event| {
            if events.next().is_some() {
                // Fork
                None
            } else {
                Some(event)
            }
        });

        event
            .and_then(|event| self.meta_elections.meta_votes(election, event))
            .and_then(|meta_votes| meta_votes.get(&peer_index))
            .into_iter()
            .flat_map(|meta_votes| meta_votes)
            .filter(move |meta_vote| {
                meta_vote.round > round || meta_vote.round == round && meta_vote.step >= step
            })
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by the peer at `peer_index`.
    fn collect_other_meta_votes(
        &self,
        election: MetaElectionHandle,
        voters: &PeerIndexSet,
        peer_index: PeerIndex,
        event: &Event<S::PublicId>,
    ) -> Vec<Vec<MetaVote>> {
        voters
            .iter()
            .filter(|voter_index| **voter_index != event.creator())
            .filter_map(|creator| {
                event
                    .last_ancestors()
                    .get(creator)
                    .map(|creator_event_index| {
                        self.meta_votes_since_round_and_step(
                            election,
                            *creator,
                            *creator_event_index,
                            peer_index,
                            0,
                            Step::ForcedTrue,
                        )
                        .cloned()
                        .collect()
                    })
            })
            .collect()
    }

    // Initialise the membership list of the creator of the given event to the same membership list
    // the creator of the other-parent had at the time of the other-parent's creation. Do nothing if
    // the event is not request or response or if the membership list is already initialised.
    fn initialise_membership_list(&mut self, event_index: EventIndex) {
        let (creator, changes) = {
            let event = if let Ok(event) = self.get_known_event(event_index) {
                event
            } else {
                return;
            };

            if event.creator() == PeerIndex::OUR {
                return;
            }

            if self
                .peer_list
                .is_peer_membership_list_initialised(event.creator())
            {
                return;
            }

            let other_parent_creator = if let Some(other_parent) = self.graph.other_parent(event) {
                other_parent.inner().creator()
            } else {
                return;
            };

            // Collect all changes to `other_parent_creator`'s membership list seen by `event`.
            let changes: Vec<_> = self
                .peer_list
                .peer_membership_list_changes(other_parent_creator)
                .iter()
                .take_while(|(index, _)| {
                    self.peer_list
                        .events_by_index(other_parent_creator, *index)
                        .filter_map(|hash| self.get_known_event(hash).ok())
                        .any(|other_event| event.sees(other_event))
                })
                .map(|(_, change)| change.clone())
                .collect();
            (event.creator(), changes)
        };

        for change in changes {
            self.peer_list.change_peer_membership_list(creator, change);
        }
    }

    // List of voters for the given meta-election.
    fn voters(&self, election: MetaElectionHandle) -> PeerIndexSet {
        self.meta_elections
            .voters(election)
            .cloned()
            .unwrap_or_else(|| self.peer_list.voter_indices().collect())
    }

    // Number of voters for the given meta-election.
    fn voter_count(&self, election: MetaElectionHandle) -> usize {
        self.meta_elections
            .voters(election)
            .map(|voters| voters.len())
            .unwrap_or_else(|| self.peer_list.voters().count())
    }

    fn unconsensused_events(
        &self,
        election: MetaElectionHandle,
    ) -> impl Iterator<Item = IndexedEventRef<S::PublicId>> {
        self.meta_elections
            .unconsensused_events(election)
            .filter_map(move |index| self.get_known_event(index).ok())
    }

    fn start_index(&self, election: MetaElectionHandle) -> usize {
        self.meta_elections
            .start_index(election)
            .unwrap_or_else(|| self.graph.len())
    }

    fn compute_consensus(
        &self,
        election: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Option<ObservationKey> {
        let last_meta_votes = self.meta_elections.meta_votes(election, event_index)?;

        let decided_meta_votes = last_meta_votes
            .iter()
            .filter_map(|(peer_index, event_votes)| {
                event_votes
                    .last()
                    .and_then(|v| v.decision)
                    .map(|v| (*peer_index, v))
            });

        if decided_meta_votes.clone().count() < self.voter_count(election) {
            return None;
        }

        self.meta_elections
            .decided_payload_key(election)
            .cloned()
            .or_else(|| self.compute_payload_for_consensus(election, decided_meta_votes))
    }

    fn compute_payload_for_consensus<I>(
        &self,
        election: MetaElectionHandle,
        decided_meta_votes: I,
    ) -> Option<ObservationKey>
    where
        I: IntoIterator<Item = (PeerIndex, bool)>,
    {
        let mut payloads: Vec<_> = decided_meta_votes
            .into_iter()
            .filter_map(|(peer_index, decision)| {
                if decision {
                    self.meta_elections
                        .first_interesting_content_by(election, peer_index)
                        .cloned()
                } else {
                    None
                }
            })
            .collect();

        // IMPORTANT: We must sort this in consistent order, so when the tie breaking rule kicks in,
        // the outcome is the same for everyone.
        payloads.sort_by(|a, b| a.hash().cmp(b.hash()));

        payloads
            .iter()
            .max_by(|lhs_payload, rhs_payload| {
                let lhs_count = payloads
                    .iter()
                    .filter(|payload_carried| lhs_payload == payload_carried)
                    .count();
                let rhs_count = payloads
                    .iter()
                    .filter(|payload_carried| rhs_payload == payload_carried)
                    .count();
                lhs_count.cmp(&rhs_count)
            })
            .cloned()
    }

    fn create_block(&self, payload_key: &ObservationKey) -> Result<Block<T, S::PublicId>> {
        let voters = self.voters(MetaElectionHandle::CURRENT);
        let votes = self
            .graph
            .iter()
            .map(|event| event.inner())
            .filter(|event| voters.contains(&event.creator()))
            .filter_map(|event| {
                let (vote, key) = event.vote_and_payload_key(&self.observations)?;
                let creator_id = self.peer_list.get(event.creator()).map(|peer| peer.id())?;
                Some((key, vote, creator_id))
            })
            .filter(|(key, _, _)| payload_key == key)
            .map(|(_, vote, creator_id)| (creator_id.clone(), vote.clone()))
            .collect();

        Block::new(&votes)
    }

    // Collects still unconsensused event from the current meta-election.
    fn collect_unconsensused_events(&self, decided_key: &ObservationKey) -> BTreeSet<EventIndex> {
        self.meta_elections
            .unconsensused_events(MetaElectionHandle::CURRENT)
            .filter(|event_index| {
                self.get_known_event(*event_index)
                    .ok()
                    .and_then(|event| event.inner().payload_key())
                    .map(|payload_key| payload_key != decided_key)
                    .unwrap_or(false)
            })
            .collect()
    }

    // Returns the number of peers that created events which are seen by event X (descendant) and
    // see event Y (ancestor). This means number of peers through which there is a directed path
    // between x and y, excluding peers contains fork.
    fn num_peers_created_events_seen_by_x_that_can_see_y(
        &self,
        x: &Event<S::PublicId>,
        y: &Event<S::PublicId>,
    ) -> usize {
        x.last_ancestors()
            .iter()
            .filter(|(peer_index, &event_index)| {
                for event_hash in self.peer_list.events_by_index(**peer_index, event_index) {
                    if let Ok(event) = self.get_known_event(event_hash) {
                        if x.sees(event) && event.sees(y) {
                            return true;
                        }
                    }
                }
                false
            })
            .count()
    }

    // Returns whether event X can strongly see the event Y during the evaluation of the given
    // election.
    fn strongly_sees<A, B>(&self, election: MetaElectionHandle, x: A, y: B) -> bool
    where
        A: AsRef<Event<S::PublicId>>,
        B: AsRef<Event<S::PublicId>>,
    {
        is_more_than_two_thirds(
            self.num_peers_created_events_seen_by_x_that_can_see_y(x.as_ref(), y.as_ref()),
            self.voter_count(election),
        )
    }

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    //
    // `opt_other_parent` will contain the other-parent this new sync event should use, unless the
    // gossip message from the peer was empty, in which case this will be `None` and we'll just use
    // `src`'s most recent event we know of.
    fn create_sync_event(
        &mut self,
        src_index: PeerIndex,
        is_request: bool,
        forking_peers: &PeerIndexSet,
        opt_other_parent: Option<EventIndex>,
    ) -> Result<()> {
        let self_parent = self.peer_list.last_event(PeerIndex::OUR).ok_or_else(|| {
            log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
            Error::Logic
        })?;

        let other_parent = match opt_other_parent {
            Some(index) => index,
            None => self.peer_list.last_event(src_index).ok_or_else(|| {
                log_or_panic!(
                    "{:?} missing last event hash of {:?}.",
                    self.our_pub_id(),
                    src_index
                );
                Error::Logic
            })?,
        };

        let sync_event = if is_request {
            Event::new_from_request(
                self_parent,
                other_parent,
                forking_peers,
                self.event_context(),
            )?
        } else {
            Event::new_from_response(
                self_parent,
                other_parent,
                forking_peers,
                self.event_context(),
            )?
        };

        let _ = self.add_event(sync_event)?;
        Ok(())
    }

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.  We should already have checked that we know `peer_id` and that we
    // have recorded at least one event from this peer before calling this function.
    fn events_to_gossip_to_peer(&self, peer_index: PeerIndex) -> Result<Vec<&Event<S::PublicId>>> {
        let last_event = if let Some(event_index) = self.peer_list.last_event(peer_index) {
            self.get_known_event(event_index)?
        } else {
            log_or_panic!("{:?} doesn't have peer {:?}", self.our_pub_id(), peer_index);
            return Err(Error::Logic);
        };

        // Events to include in the result. Initially start with including everything...
        let mut inclusion_list = vec![true; self.graph.len()];

        // ...then exclude events that are ancestors of `last_event`, because the peer already has
        // them.
        for event in self.graph.ancestors(last_event) {
            inclusion_list[event.topological_index()] = false;
        }

        Ok(self
            .graph
            .iter()
            .filter(|event| inclusion_list[event.topological_index()])
            .map(|event| event.inner())
            .collect())
    }

    // Get the responsiveness threshold based on the current number of peers.
    fn responsiveness_threshold(&self, election: MetaElectionHandle) -> usize {
        (self.voter_count(election) as f64).log2().ceil() as usize
    }

    fn create_accusation_event(
        &mut self,
        offender: PeerIndex,
        malice: Malice<T, S::PublicId>,
    ) -> Result<()> {
        let offender = self.peer_list.get_known(offender)?.id().clone();
        let event = Event::new_from_observation(
            self.our_last_event_index()?,
            Observation::Accusation { offender, malice },
            self.event_context_mut(),
        )?;

        let _ = self.add_event(event)?;
        Ok(())
    }

    fn create_accusation_events(&mut self) -> Result<()> {
        let pending_accusations = mem::replace(&mut self.pending_accusations, vec![]);
        for (offender, malice) in pending_accusations {
            self.create_accusation_event(offender, malice)?;
        }

        Ok(())
    }

    fn event_context(&self) -> EventContextRef<T, S> {
        EventContextRef {
            graph: &self.graph,
            peer_list: &self.peer_list,
            observations: &self.observations,
        }
    }

    fn event_context_mut(&mut self) -> EventContextMut<T, S> {
        EventContextMut {
            graph: &self.graph,
            peer_list: &self.peer_list,
            observations: &mut self.observations,
            consensus_mode: self.consensus_mode,
        }
    }

    #[cfg(any(all(test, feature = "mock"), feature = "malice-detection"))]
    fn event_payload<'a>(
        &'a self,
        event: &Event<S::PublicId>,
    ) -> Option<&'a Observation<T, S::PublicId>> {
        event
            .payload_key()
            .and_then(|key| self.observations.get(key))
            .map(|info| &info.observation)
    }

    #[cfg(any(all(test, feature = "mock"), feature = "malice-detection"))]
    fn event_creator_id<'a>(&'a self, event: &Event<S::PublicId>) -> Result<&'a S::PublicId> {
        self.peer_list
            .get(event.creator())
            .map(|peer| peer.id())
            .ok_or_else(|| {
                log_or_panic!(
                    "{:?} doesn't know the creator of {:?}",
                    self.our_pub_id(),
                    event
                );
                Error::Logic
            })
    }
}

#[cfg(feature = "malice-detection")]
impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    fn detect_malice_before_process(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        // NOTE: `detect_incorrect_genesis` must come first.
        self.detect_incorrect_genesis(event)?;

        self.detect_other_parent_by_same_creator(event)?;
        self.detect_self_parent_by_different_creator(event)?;

        self.detect_unexpected_genesis(event);
        self.detect_missing_genesis(event);
        self.detect_duplicate_vote(event);
        self.detect_fork(event);
        self.detect_invalid_accusation(event);

        // TODO: detect other forms of malice here

        Ok(())
    }

    fn detect_malice_after_process(&mut self, event_index: EventIndex) {
        self.detect_invalid_gossip_creator(event_index);
    }

    // Detect if the event carries an `Observation::Genesis` that doesn't match what we'd expect.
    fn detect_incorrect_genesis(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        let (offender, malice) =
            if let Some(Observation::Genesis(ref group)) = self.event_payload(event) {
                if group.iter().collect::<BTreeSet<_>>() != self.genesis_group() {
                    (event.creator(), Malice::IncorrectGenesis(*event.hash()))
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            };

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        self.create_accusation_event(offender, malice)?;
        Err(Error::InvalidEvent)
    }

    // Detect if the event's other_parent has the same creator as this event.
    fn detect_other_parent_by_same_creator(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        if let Some(other_parent) = self.graph.other_parent(event) {
            if other_parent.creator() != event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        let packed_event = event.pack(self.event_context())?;
        self.create_accusation_event(
            event.creator(),
            Malice::OtherParentBySameCreator(Box::new(packed_event)),
        )?;
        Err(Error::InvalidEvent)
    }

    // Detect if the event's self_parent has the different creator as this event.
    fn detect_self_parent_by_different_creator(
        &mut self,
        event: &Event<S::PublicId>,
    ) -> Result<()> {
        if let Some(self_parent) = self.graph.self_parent(event) {
            if self_parent.creator() == event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        let packed_event = event.pack(self.event_context())?;
        self.create_accusation_event(
            event.creator(),
            Malice::SelfParentByDifferentCreator(Box::new(packed_event)),
        )?;
        Err(Error::InvalidEvent)
    }

    // Detect whether the event carries unexpected `Observation::Genesis`.
    fn detect_unexpected_genesis(&mut self, event: &Event<S::PublicId>) {
        let accuse = {
            let payload = if let Some(payload) = self.event_payload(event) {
                payload
            } else {
                return;
            };

            let genesis_group = if let Observation::Genesis(ref group) = *payload {
                group
            } else {
                return;
            };

            let creator_id = if let Ok(id) = self.event_creator_id(event) {
                id
            } else {
                return;
            };

            // - the creator is not member of the genesis group, or
            // - the self-parent of the event is not initial event
            !genesis_group.contains(creator_id)
                || self
                    .graph
                    .self_parent(event)
                    .map_or(true, |self_parent| !self_parent.is_initial())
        };

        if accuse {
            self.accuse(event.creator(), Malice::UnexpectedGenesis(*event.hash()));
        }
    }

    // Detect when the first event by a peer belonging to genesis doesn't carry genesis
    fn detect_missing_genesis(&mut self, event: &Event<S::PublicId>) {
        if event.index_by_creator() != 1 {
            return;
        }

        if let Some(&Observation::Genesis(_)) = self.event_payload(event) {
            return;
        }

        let accuse = {
            let creator_id = if let Ok(id) = self.event_creator_id(event) {
                id
            } else {
                return;
            };

            self.genesis_group().contains(creator_id)
        };

        if accuse {
            self.accuse(event.creator(), Malice::MissingGenesis(*event.hash()));
        }
    }

    // Detect that if the event carries a vote, there is already one or more votes with the same
    // observation by the same creator.
    fn detect_duplicate_vote(&mut self, event: &Event<S::PublicId>) {
        let other_hash = {
            let payload = if let Some(payload) = self.event_payload(event) {
                payload
            } else {
                return;
            };

            let mut duplicates = self
                .peer_list
                .peer_events(event.creator())
                .rev()
                .filter_map(|index| self.get_known_event(index).ok())
                .filter(|event| {
                    self.event_payload(event)
                        .map_or(false, |event_payload| event_payload == payload)
                })
                .map(|event| *event.hash())
                .take(2);

            let hash = if let Some(hash) = duplicates.next() {
                // One duplicate found - raise the accusation.
                hash
            } else {
                // No duplicates found - do not raise the accusation.
                return;
            };

            if duplicates.next().is_some() {
                // More than one duplicate found - the accusation should have already been raised,
                // so don't raise it again.
                return;
            }

            hash
        };

        self.accuse(
            event.creator(),
            Malice::DuplicateVote(other_hash, *event.hash()),
        );
    }

    // Detect whether the event incurs a fork.
    fn detect_fork(&mut self, event: &Event<S::PublicId>) {
        if self.peer_list.last_event(event.creator()) != event.self_parent() {
            if let Some(self_parent_hash) = self.graph.self_parent(event).map(|event| *event.hash())
            {
                self.accuse(event.creator(), Malice::Fork(self_parent_hash));
            }
        }
    }

    fn detect_invalid_accusation(&mut self, event: &Event<S::PublicId>) {
        {
            let their_accusation = match self.event_payload(event) {
                Some(&Observation::Accusation {
                    ref offender,
                    ref malice,
                }) => {
                    if !malice.is_provable() {
                        return;
                    }

                    let offender = if let Some(index) = self.peer_list.get_index(offender) {
                        index
                    } else {
                        return;
                    };

                    (offender, malice)
                }
                _ => return,
            };

            // First try to find the same accusation in our pending accusations...
            let found = self
                .pending_accusations
                .iter()
                .any(|&(our_offender, ref our_malice)| {
                    their_accusation == (our_offender, our_malice)
                });
            if found {
                return;
            }

            // ...then in our events...
            let found = self
                .peer_list
                .our_events()
                .rev()
                .filter_map(|hash| self.get_known_event(hash).ok())
                .filter_map(|event| {
                    if let Some(&Observation::Accusation {
                        ref offender,
                        ref malice,
                    }) = self.event_payload(event.inner())
                    {
                        Some((offender, malice))
                    } else {
                        None
                    }
                })
                .filter_map(|(offender_id, malice)| {
                    self.peer_list
                        .get_index(offender_id)
                        .map(|index| (index, malice))
                })
                .any(|our_accusation| their_accusation == our_accusation);
            if found {
                return;
            }
        }

        // ..if not found, their accusation is invalid.
        self.accuse(event.creator(), Malice::InvalidAccusation(*event.hash()))
    }

    fn detect_invalid_gossip_creator(&mut self, event_index: EventIndex) {
        let accusation = {
            let event = if let Ok(event) = self.get_known_event(event_index) {
                event
            } else {
                return;
            };

            let other_parent = if let Some(parent) = self.graph.other_parent(event) {
                parent
            } else {
                return;
            };

            let membership_list = if let Some(list) = self
                .peer_list
                .peer_membership_list_snapshot_excluding_last_remove(
                    event.creator(),
                    event.index_by_creator(),
                ) {
                list
            } else {
                // The membership list is not yet initialised - skip the detection.
                return;
            };

            if membership_list.contains(&other_parent.creator()) {
                None
            } else {
                Some((event.creator(), *event.hash()))
            }
        };

        if let Some((offender, event_hash)) = accusation {
            self.accuse(offender, Malice::InvalidGossipCreator(event_hash))
        }
    }

    fn detect_premature_gossip(&self) -> Result<()> {
        self.confirm_self_state(PeerState::VOTE)
            .map_err(|_| Error::PrematureGossip)
    }

    fn detect_spam(&mut self, src_index: PeerIndex, known_event_index: EventIndex) {
        if self.unprovable_offenders.contains(&src_index) {
            // Already accused.
            return;
        }

        let spam = {
            let their_event = self
                .peer_list
                .last_gossiped_event_by(src_index)
                .and_then(|index| self.get_known_event(index).ok())
                .and_then(|event| self.last_ancestor_by(event, src_index));
            let their_event = if let Some(their_event) = their_event {
                their_event
            } else {
                return;
            };

            let known_event = if let Ok(event) = self.get_known_event(known_event_index) {
                event
            } else {
                return;
            };

            self.last_ancestor_by(their_event, PeerIndex::OUR)
                .map(|our_event| self.graph.is_descendant(our_event, known_event))
                .unwrap_or(false)
        };

        if spam {
            let _ = self.unprovable_offenders.insert(src_index);
            self.accuse(src_index, Malice::Unprovable(UnprovableMalice::Spam));
        }
    }

    fn accuse(&mut self, offender: PeerIndex, malice: Malice<T, S::PublicId>) {
        self.pending_accusations.push((offender, malice));
    }

    fn accusations_by_peer_since(
        &self,
        peer_index: PeerIndex,
        oldest_event: EventIndex,
    ) -> Accusations<T, S::PublicId> {
        self.graph
            .iter_from(oldest_event.topological_index())
            .filter(|event| event.creator() == peer_index)
            .filter_map(|event| match self.event_payload(event.inner()) {
                Some(Observation::Accusation { offender, malice }) => Some((offender, malice)),
                _ => None,
            })
            .filter_map(|(offender, malice)| {
                self.peer_list
                    .get_index(offender)
                    .map(|offender| (offender, malice.clone()))
            })
            .collect()
    }

    fn malicious_event_is_ancestor_of_this_event(
        &self,
        malice: &Malice<T, S::PublicId>,
        event: EventIndex,
    ) -> bool {
        let event = if let Some(event) = self.graph.get(event) {
            event
        } else {
            return false;
        };

        match malice {
            Malice::UnexpectedGenesis(hash)
            | Malice::MissingGenesis(hash)
            | Malice::IncorrectGenesis(hash)
            | Malice::InvalidAccusation(hash)
            | Malice::InvalidGossipCreator(hash)
            | Malice::Accomplice(hash) => self
                .graph
                .get_index(hash)
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| self.graph.is_descendant(event, malicious_event))
                .unwrap_or(false),

            Malice::DuplicateVote(hash0, hash1) => {
                self.graph
                    .get_index(hash0)
                    .and_then(|index| self.graph.get(index))
                    .map(|malicious_event0| self.graph.is_descendant(event, malicious_event0))
                    .unwrap_or(false)
                    && self
                        .graph
                        .get_index(hash1)
                        .and_then(|index| self.graph.get(index))
                        .map(|malicious_event1| self.graph.is_descendant(event, malicious_event1))
                        .unwrap_or(false)
            }
            Malice::Fork(hash) => self
                .graph
                .get_index(hash)
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| {
                    self.graph.is_descendant(event, malicious_event)
                        && event.is_forking_peer(malicious_event.creator())
                })
                .unwrap_or(false),
            Malice::OtherParentBySameCreator(packed_event)
            | Malice::SelfParentByDifferentCreator(packed_event) => self
                .graph
                .get_index(&packed_event.compute_hash())
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| self.graph.is_descendant(event, malicious_event))
                .unwrap_or(false),
            Malice::Unprovable(_) => false,
        }
    }

    fn act_on_accomplice_accusation_candidates_we_can_now_prove(
        &mut self,
        current: EventIndex,
    ) -> Result<()> {
        let accomplice_accusations_we_can_act_on = self
            .candidate_accomplice_accusations
            .iter()
            .filter(|(index, accomplice_accusation)| {
                self.graph
                    .iter_from(index.topological_index() + 1)
                    .filter(|event| event.creator() == accomplice_accusation.creator)
                    .any(|event| {
                        self.event_payload(&*event)
                            .map(|payload| match payload {
                                Observation::Accusation { .. } => false,
                                _ => true,
                            })
                            .unwrap_or(true)
                    })
            })
            .cloned()
            .collect::<CandidateAccompliceAccusations<_, _>>();

        for (index, accomplice) in accomplice_accusations_we_can_act_on {
            let can_still_detect_accomplice = self
                .detect_accomplice_for_our_accusations(current, accomplice.starting_index)?
                .iter()
                .any(|(_, mal)| mal == &accomplice.against);

            if can_still_detect_accomplice {
                // Repoint the malice event to the event where we're actually certain
                let current = *self.get_known_event(current)?.hash();
                self.accuse(accomplice.creator, Malice::Accomplice(current));
            }
            let _ = self
                .candidate_accomplice_accusations
                .remove(&(index, accomplice));
        }
        Ok(())
    }

    fn detect_accomplice(
        &mut self,
        event: EventIndex,
        first_event_by_peer_in_packed_event: &BTreeMap<S::PublicId, EventHash>,
    ) -> Result<()> {
        let (event_hash, creator, starting_index) = {
            let event = self.get_known_event(event)?;

            if self.unprovable_offenders.contains(&event.creator()) {
                // Can only accuse the peer once anyway
                return Ok(());
            }

            let creator_id = self.event_creator_id(&*event)?;
            let starting_index = first_event_by_peer_in_packed_event
                .get(creator_id)
                .and_then(|event| self.graph.get_index(event))
                .ok_or(Error::Logic)?;

            (*event.hash(), event.creator(), starting_index)
        };

        for (_, malice) in self.detect_accomplice_for_our_accusations(event, starting_index)? {
            let _ = self.candidate_accomplice_accusations.insert((
                event,
                CandidateAccompliceAccusation {
                    creator,
                    accusation: Malice::Accomplice(event_hash),
                    against: malice,
                    starting_index,
                },
            ));
        }

        Ok(())
    }

    fn detect_accomplice_for_our_accusations(
        &self,
        event: EventIndex,
        starting_event: EventIndex,
    ) -> Result<Accusations<T, S::PublicId>> {
        let creator = self.get_known_event(event)?.creator();
        let our_accusations = self.accusations_by_peer_since(PeerIndex::OUR, starting_event);
        let accusations_by_peer_since_starter_event =
            self.accusations_by_peer_since(creator, starting_event);

        Ok(self
            .pending_accusations
            .iter()
            .chain(our_accusations.iter())
            .filter(|(offender, _)| offender != &creator)
            .filter(|(_, malice)| self.malicious_event_is_ancestor_of_this_event(&malice, event))
            .filter(|(offender, malice)| {
                !accusations_by_peer_since_starter_event
                    .iter()
                    .any(|(off, mal)| (off, mal) == (offender, &malice))
            })
            .cloned()
            .collect())
    }

    fn genesis_group(&self) -> BTreeSet<&S::PublicId> {
        self.graph
            .iter()
            .filter_map(|event| {
                let observation = self.event_payload(&*event)?;
                if let Observation::Genesis(ref gen) = *observation {
                    Some(gen.iter().collect())
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_else(|| self.peer_list.voters().map(|(_, peer)| peer.id()).collect())
    }

    // Returns the last ancestor of the given event created by the given peer, if any.
    fn last_ancestor_by<'a>(
        &'a self,
        event: IndexedEventRef<'a, S::PublicId>,
        creator: PeerIndex,
    ) -> Option<IndexedEventRef<'a, S::PublicId>> {
        use gossip::LastAncestor;

        match event.last_ancestor_by(creator) {
            LastAncestor::Some(index) => self
                .peer_list
                .events_by_index(creator, index)
                .next()
                .and_then(|index| self.get_known_event(index).ok()),
            LastAncestor::None => None,
            LastAncestor::Fork => self
                .graph
                .ancestors(event)
                .find(|ancestor| ancestor.creator() == creator),
        }
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
    fn drop(&mut self) {
        if ::std::thread::panicking() {
            dump_graph::to_file(
                self.our_pub_id(),
                &self.graph,
                &self.meta_elections,
                &self.peer_list,
                &self.observations,
            );
        }
    }
}

// What to do after processing the current event.
enum PostProcessAction {
    // Continue with the next event (if any)
    Continue,
    // Restart processing events from the given index.
    Restart(usize),
}

type Accusations<T, P> = Vec<(PeerIndex, Malice<T, P>)>;

#[cfg(feature = "malice-detection")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CandidateAccompliceAccusation<T: NetworkEvent, P: PublicId> {
    creator: PeerIndex,
    accusation: Malice<T, P>,
    against: Malice<T, P>,
    // The start of the range where source accusations are considered. This is purely a performance
    // optimisation.
    starting_index: EventIndex,
}

#[cfg(feature = "malice-detection")]
type CandidateAccompliceAccusations<T, P> =
    BTreeSet<(EventIndex, CandidateAccompliceAccusation<T, P>)>;

#[cfg(feature = "malice-detection")]
fn collect_first_self_parents<T: NetworkEvent, S: SecretId>(
    packed_events: &[PackedEvent<T, S::PublicId>],
) -> BTreeMap<S::PublicId, EventHash> {
    let mut events = BTreeMap::new();
    packed_events.iter().for_each(|event| {
        if let Some(hash) = event.self_parent() {
            let _ = events.entry(event.creator().clone()).or_insert(*hash);
        }
    });
    events
}

#[cfg(any(feature = "testing", all(test, feature = "mock")))]
impl Parsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(mut parsed_contents: ParsedContents) -> Self {
        let peer_list = PeerList::new(parsed_contents.our_id);
        let mut parsec = Parsec::empty(
            peer_list,
            PeerIndexSet::default(),
            ConsensusMode::Supermajority,
        );

        for event in &parsed_contents.graph {
            if let Some(payload_key) = event.payload_key() {
                if let Some(info) = parsed_contents.observations.get_mut(payload_key) {
                    if event.creator() == PeerIndex::OUR {
                        info.created_by_us = true;
                    }
                }
            }
        }

        for consensused in parsed_contents.meta_elections.consensus_history() {
            let _ = parsed_contents
                .observations
                .get_mut(consensused)
                .map(|info| info.consensused = true);
        }

        parsec.graph = parsed_contents.graph;
        parsec.meta_elections = parsed_contents.meta_elections;
        parsec.peer_list = parsed_contents.peer_list;
        parsec.observations = parsed_contents.observations;
        parsec
    }
}

/// Wrapper around `Parsec` that exposes additional functionality useful for testing.
#[cfg(all(test, feature = "mock"))]
pub(crate) struct TestParsec<T: NetworkEvent, S: SecretId>(Parsec<T, S>);

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> TestParsec<T, S> {
    pub fn from_genesis(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Self {
        TestParsec(Parsec::from_genesis(
            our_id,
            genesis_group,
            ConsensusMode::Supermajority,
        ))
    }

    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
    ) -> Self {
        TestParsec(Parsec::from_existing(
            our_id,
            genesis_group,
            section,
            ConsensusMode::Supermajority,
        ))
    }

    pub fn graph(&self) -> &Graph<S::PublicId> {
        &self.0.graph
    }

    pub fn peer_list(&self) -> &PeerList<S> {
        &self.0.peer_list
    }

    pub fn meta_elections(&self) -> &MetaElections {
        &self.0.meta_elections
    }

    pub fn consensused_blocks(&self) -> impl Iterator<Item = &Block<T, S::PublicId>> {
        self.0.consensused_blocks.iter()
    }

    pub fn create_sync_event(
        &mut self,
        src: &S::PublicId,
        is_request: bool,
        forking_peers: &PeerIndexSet,
        other_parent: Option<EventHash>,
    ) -> Result<()> {
        let src_index = unwrap!(self.0.peer_list.get_index(src));
        let other_parent = other_parent
            .as_ref()
            .map(|hash| unwrap!(self.0.graph.get_index(hash)));
        self.0
            .create_sync_event(src_index, is_request, forking_peers, other_parent)
    }

    pub fn change_peer_state(&mut self, peer_id: &S::PublicId, state: PeerState) {
        let peer_index = unwrap!(self.0.peer_list.get_index(peer_id));
        self.0.peer_list.change_peer_state(peer_index, state)
    }

    pub fn pack_event(&self, event: &Event<S::PublicId>) -> PackedEvent<T, S::PublicId> {
        unwrap!(event.pack(self.0.event_context()))
    }

    pub fn unpack_and_add_event(
        &mut self,
        event: PackedEvent<T, S::PublicId>,
    ) -> Result<EventIndex> {
        match Event::unpack(event, &PeerIndexSet::default(), self.0.event_context_mut())? {
            UnpackedEvent::New(event) => self.0.add_event(event),
            UnpackedEvent::Known(index) => Ok(index),
        }
    }

    // Warning: only add events created using this instance of `Parsec`. Adding an event from other
    // instance is not detectable and might lead to incorrect test results. To add event from other
    // instance, first `pack_event` it using that other instance, then add it using
    // `unpack_and_add_event`.
    pub fn add_event(&mut self, event: Event<S::PublicId>) -> Result<EventIndex> {
        self.0.add_event(event)
    }

    #[cfg(feature = "malice-detection")]
    pub fn our_last_event_index(&self) -> EventIndex {
        unwrap!(self.0.our_last_event_index())
    }

    #[cfg(feature = "malice-detection")]
    pub fn remove_last_event(&mut self) -> Option<(EventIndex, Event<S::PublicId>)> {
        self.graph.remove_last()
    }

    #[cfg(feature = "malice-detection")]
    pub fn pending_accusations(&self) -> &Accusations<T, S::PublicId> {
        &self.0.pending_accusations
    }

    #[cfg(feature = "malice-detection")]
    pub fn add_peer(&mut self, peer_id: S::PublicId, state: PeerState) {
        let _ = self.0.peer_list.add_peer(peer_id, state);
    }

    #[cfg(feature = "malice-detection")]
    pub fn restart_consensus(&mut self) -> Result<()> {
        self.0.process_events(0)
    }

    pub fn event_payload(
        &self,
        event: &Event<S::PublicId>,
    ) -> Option<&Observation<T, S::PublicId>> {
        self.0.event_payload(event)
    }

    pub fn event_creator_id(&self, event: &Event<S::PublicId>) -> &S::PublicId {
        unwrap!(self.0.event_creator_id(event))
    }

    #[cfg(feature = "malice-detection")]
    pub fn event_context(&self) -> EventContextRef<T, S> {
        self.0.event_context()
    }

    pub fn event_context_mut(&mut self) -> EventContextMut<T, S> {
        self.0.event_context_mut()
    }
}

#[cfg(all(test, feature = "mock"))]
impl TestParsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(parsed_contents: ParsedContents) -> Self {
        TestParsec(Parsec::from_parsed_contents(parsed_contents))
    }
}

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> Deref for TestParsec<T, S> {
    type Target = Parsec<T, S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> DerefMut for TestParsec<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Assert that the two parsec instances have the same events modulo their insertion order.
#[cfg(all(test, feature = "testing"))]
pub(crate) fn assert_same_events<T: NetworkEvent, S: SecretId>(a: &Parsec<T, S>, b: &Parsec<T, S>) {
    use gossip::GraphSnapshot;

    let a = GraphSnapshot::new(&a.graph);
    let b = GraphSnapshot::new(&b.graph);

    assert_eq!(a, b)
}
