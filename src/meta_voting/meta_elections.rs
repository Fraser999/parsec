// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_event::MetaEvent;
use super::meta_vote::MetaVote;
use fnv::FnvHashMap;
use gossip::EventIndex;
use id::PublicId;
use observation::{ObservationHash, ObservationKey};
use round_hash::RoundHash;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug};
use std::{iter, mem, usize};

/// Handle that uniquely identifies a `MetaElection`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub(crate) struct MetaElectionHandle(pub(crate) usize);

impl MetaElectionHandle {
    /// Handle to the current election.
    pub const CURRENT: Self = MetaElectionHandle(usize::MAX);
}

impl Debug for MetaElectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MetaElectionHandle(")?;

        if *self == Self::CURRENT {
            write!(f, "CURRENT")?
        } else {
            write!(f, "{}", self.0)?
        }

        write!(f, ")")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetaElection {
    pub(crate) meta_events: FnvHashMap<EventIndex, MetaEvent>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    pub(crate) round_hashes: PeerIndexMap<Vec<RoundHash>>,
    // Set of peers participating in this meta-election, i.e. all voters at the time this
    // meta-election has been created.
    pub(crate) all_voters: PeerIndexSet,
    // Set of peers which we haven't yet detected deciding this meta-election.
    pub(crate) undecided_voters: PeerIndexSet,
    // The indices of events for each peer that have a non-empty set of `interesting_content`.
    pub(crate) interesting_events: PeerIndexMap<VecDeque<EventIndex>>,
    // Length of `MetaElections::consensus_history` at the time this meta-election was created.
    pub(crate) consensus_len: usize,
    // Key of the payload decided by this meta-election.
    pub(crate) payload_key: Option<ObservationKey>,
    // Set of all events that carry a payload that hasn't yet been consensused.
    pub(crate) unconsensused_events: BTreeSet<EventIndex>,
}

impl MetaElection {
    fn new(
        voters: PeerIndexSet,
        consensus_len: usize,
        unconsensused_events: BTreeSet<EventIndex>,
    ) -> Self {
        MetaElection {
            meta_events: FnvHashMap::default(),
            round_hashes: PeerIndexMap::default(),
            all_voters: voters.clone(),
            undecided_voters: voters,
            interesting_events: PeerIndexMap::default(),
            consensus_len,
            payload_key: None,
            unconsensused_events,
        }
    }

    fn initialise<'a, I, P>(&mut self, peer_ids: I, initial_hash: ObservationHash)
    where
        I: IntoIterator<Item = (PeerIndex, &'a P)>,
        P: PublicId + 'a,
    {
        self.round_hashes = peer_ids
            .into_iter()
            .map(|(index, id)| {
                let round_hash = RoundHash::new(id, initial_hash);
                (index, vec![round_hash])
            })
            .collect();

        // Clearing these caches is needed to be able to reprocess the whole graph outside of
        // consensus, which we sometimes need in tests.
        self.meta_events.clear();
        self.interesting_events.clear();
    }

    fn is_already_interesting_content(
        &self,
        creator: PeerIndex,
        payload_key: &ObservationKey,
    ) -> bool {
        self.interesting_events
            .get(&creator)
            .map_or(false, |indices| {
                indices.iter().any(|index| {
                    if let Some(meta_event) = self.meta_events.get(index) {
                        meta_event.interesting_content.contains(payload_key)
                    } else {
                        false
                    }
                })
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetaElections {
    // Index of next decided meta-election
    next_index: usize,
    // Current ongoing meta-election.
    current_election: MetaElection,
    // Meta-elections that are already decided by us, but not by all the other peers.
    previous_elections: BTreeMap<MetaElectionHandle, MetaElection>,
    // Keys of the consensused blocks' payloads in the order they were consensused.
    consensus_history: Vec<ObservationKey>,
}

impl MetaElections {
    pub fn new(voters: PeerIndexSet) -> Self {
        MetaElections {
            next_index: 0,
            current_election: MetaElection::new(voters, 0, BTreeSet::new()),
            previous_elections: BTreeMap::new(),
            consensus_history: Vec::new(),
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn from_map_and_history(
        mut elections_map: BTreeMap<MetaElectionHandle, MetaElection>,
        consensus_history: Vec<ObservationKey>,
    ) -> Self {
        let current_election = unwrap!(elections_map.remove(&MetaElectionHandle::CURRENT));
        MetaElections {
            next_index: consensus_history.len(),
            current_election,
            previous_elections: elections_map,
            consensus_history,
        }
    }

    pub fn all<'a>(&'a self) -> impl Iterator<Item = MetaElectionHandle> + 'a {
        // NOTE: make sure we return the elections in reverse chronological order (newest first).
        // Otherwise the optimization that tries to reuse interesting content from previous
        // meta-elections (see `Parsec::previous_interesting_content`) might break the consensus.
        self.previous_elections
            .keys()
            .cloned()
            .chain(iter::once(MetaElectionHandle::CURRENT))
            .rev()
    }

    /// Elections that were already decided by us, but not by the given peer.
    pub fn undecided_by<'a>(
        &'a self,
        peer_index: PeerIndex,
    ) -> impl Iterator<Item = MetaElectionHandle> + 'a {
        self.previous_elections
            .iter()
            .filter(move |(_, election)| election.undecided_voters.contains(&peer_index))
            .map(|(handle, _)| *handle)
    }

    pub fn preceding(&self, handle: MetaElectionHandle) -> Option<MetaElectionHandle> {
        use std::ops::Bound::{Excluded, Unbounded};
        self.previous_elections
            .range((Unbounded, Excluded(&handle)))
            .rev()
            .map(|(handle, _)| *handle)
            .next()
    }

    pub fn add_meta_event(
        &mut self,
        handle: MetaElectionHandle,
        event_index: EventIndex,
        creator: PeerIndex,
        meta_event: MetaEvent,
    ) {
        let election = if let Some(election) = self.get_mut(handle) {
            election
        } else {
            return;
        };

        // Update round hashes.
        for (peer_id, event_votes) in &meta_event.meta_votes {
            let hashes = if let Some(hashes) = election.round_hashes.get_mut(&peer_id) {
                hashes
            } else {
                continue;
            };

            for meta_vote in event_votes {
                while hashes.len() < meta_vote.round + 1 {
                    let next_round_hash = hashes[hashes.len() - 1].increment_round();
                    hashes.push(next_round_hash);
                }
            }
        }

        // Update interesting events
        if !meta_event.interesting_content.is_empty() {
            election
                .interesting_events
                .entry(creator)
                .or_insert_with(VecDeque::new)
                .push_back(event_index);
        }

        // Insert the meta-event itself.
        let _ = election.meta_events.insert(event_index, meta_event);
    }

    pub fn meta_event(
        &self,
        handle: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Option<&MetaEvent> {
        self.get(handle)
            .and_then(|election| election.meta_events.get(&event_index))
    }

    pub fn meta_votes(
        &self,
        handle: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Option<&PeerIndexMap<Vec<MetaVote>>> {
        self.get(handle)
            .and_then(|election| election.meta_events.get(&event_index))
            .map(|meta_event| &meta_event.meta_votes)
    }

    pub fn round_hashes(
        &self,
        handle: MetaElectionHandle,
        peer_index: PeerIndex,
    ) -> Option<&Vec<RoundHash>> {
        self.get(handle)
            .and_then(|e| e.round_hashes.get(&peer_index))
    }

    /// Payload decided by the given meta-election, if any.
    pub fn decided_payload_key(&self, handle: MetaElectionHandle) -> Option<&ObservationKey> {
        self.get(handle)
            .and_then(|election| election.payload_key.as_ref())
    }

    /// List of voters participating in the given meta-election.
    pub fn voters(&self, handle: MetaElectionHandle) -> Option<&PeerIndexSet> {
        self.get(handle).map(|election| &election.all_voters)
    }

    pub fn consensus_history(&self) -> &[ObservationKey] {
        &self.consensus_history
    }

    pub fn interesting_events(
        &self,
        handle: MetaElectionHandle,
    ) -> impl Iterator<Item = (PeerIndex, &VecDeque<EventIndex>)> {
        self.get(handle).into_iter().flat_map(|election| {
            election
                .interesting_events
                .iter()
                .map(|(peer_index, event_indices)| (*peer_index, event_indices))
        })
    }

    pub fn first_interesting_content_by(
        &self,
        handle: MetaElectionHandle,
        creator: PeerIndex,
    ) -> Option<&ObservationKey> {
        let election = self.get(handle)?;
        let event_hash = election
            .interesting_events
            .get(&creator)
            .and_then(VecDeque::front)?;
        let meta_event = election.meta_events.get(event_hash)?;

        meta_event.interesting_content.first()
    }

    pub fn is_already_interesting_content(
        &self,
        handle: MetaElectionHandle,
        creator: PeerIndex,
        payload_key: &ObservationKey,
    ) -> bool {
        self.get(handle)
            .map(|election| election.is_already_interesting_content(creator, payload_key))
            .unwrap_or(false)
    }

    pub fn is_already_consensused(
        &self,
        handle: MetaElectionHandle,
        payload_key: &ObservationKey,
    ) -> bool {
        self.get(handle)
            .map(|election| {
                self.consensus_history()[..election.consensus_len].contains(payload_key)
            })
            .unwrap_or(false)
    }

    /// Topological index of the first unconsensused payload-carrying event for the given election.
    pub fn start_index(&self, handle: MetaElectionHandle) -> Option<usize> {
        // `unconsensused_events` are already sorted topologically, so just return the first one.
        self.get(handle)
            .and_then(|election| election.unconsensused_events.iter().next())
            .map(|event_index| event_index.topological_index())
    }

    /// Creates new election and returns handle of the previous election.
    pub fn new_election(
        &mut self,
        payload_key: ObservationKey,
        voters: PeerIndexSet,
        unconsensused_events: BTreeSet<EventIndex>,
    ) -> MetaElectionHandle {
        self.consensus_history.push(payload_key);

        let new = MetaElection::new(voters, self.consensus_history.len(), unconsensused_events);

        let mut previous = mem::replace(&mut self.current_election, new);
        previous.payload_key = Some(payload_key);

        let handle = self.next_handle();
        let _ = self.previous_elections.insert(handle, previous);

        handle
    }

    /// Mark the given election as decided by the given peer. If there are no more undecided peers,
    /// the election is removed.
    pub fn mark_as_decided(&mut self, handle: MetaElectionHandle, peer_index: PeerIndex) {
        trace!(
            "mark_as_decided: Marking meta-election {:?} as decided by {:?}",
            handle,
            peer_index
        );
        if let Entry::Occupied(mut entry) = self.previous_elections.entry(handle) {
            let _ = entry.get_mut().undecided_voters.remove(&peer_index);
            if entry.get().undecided_voters.is_empty() {
                trace!("mark_as_decided: Removing meta-election {:?}", handle);
                let _ = entry.remove();
            }
        } else {
            Self::not_found(handle)
        }
    }

    pub fn handle_peer_removed(&mut self, peer_index: PeerIndex) {
        let _ = self.current_election.undecided_voters.remove(&peer_index);

        let mut to_remove = Vec::new();
        for (handle, election) in &mut self.previous_elections {
            let _ = election.undecided_voters.remove(&peer_index);
            if election.undecided_voters.is_empty() {
                to_remove.push(*handle);
            }
        }
        for handle in to_remove {
            let _ = self.previous_elections.remove(&handle);
        }
    }

    pub fn initialise_current_election<'a, I, P>(&mut self, peer_ids: I)
    where
        I: IntoIterator<Item = (PeerIndex, &'a P)>,
        P: PublicId + 'a,
    {
        let hash = self
            .consensus_history
            .last()
            .map(|key| *key.hash())
            .unwrap_or(ObservationHash::ZERO);
        self.current_election.initialise(peer_ids, hash);
    }

    #[cfg(feature = "dump-graphs")]
    pub fn current_meta_events(&self) -> &FnvHashMap<EventIndex, MetaEvent> {
        &self.current_election.meta_events
    }

    pub fn add_unconsensused_event(&mut self, event_index: EventIndex) {
        // We need to add the new event to all ongoing meta-elections, not just the current one.
        // If we only added it to the current one, the `previous_interesting_content` method in
        // `Parsec` might give incorrect results, possibly leading to broken consensus. Consider
        // this example:
        //
        // 1. We decide the current meta-election (let's call it M), thus freezing it's
        //    `unconsensused_events`.
        // 2. We keep adding new meta-events to meta-election M, because we are still evaluating
        //    it from the point of view of other peers.
        // 3. Some time later, we add an event that carries an observation X. This event is NOT
        //    added to the `unconsensused_events` of meta-election M.
        // 4. So from that point on, no meta-event created for meta-election M will ever have X
        //    among its interesting content.
        // 5. So `previous_interesting_content` is now broken, because it might return `Some` of
        //    a `Vec` that doesn't contain X, event though it either should have, or it should have
        //    returned `None`
        for election in
            iter::once(&mut self.current_election).chain(self.previous_elections.values_mut())
        {
            let _ = election.unconsensused_events.insert(event_index);
        }
    }

    pub fn unconsensused_events<'a>(
        &'a self,
        handle: MetaElectionHandle,
    ) -> impl Iterator<Item = EventIndex> + 'a {
        self.get(handle)
            .into_iter()
            .flat_map(|election| election.unconsensused_events.iter().cloned())
    }

    pub(crate) fn get(&self, handle: MetaElectionHandle) -> Option<&MetaElection> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&self.current_election)
        } else if let Some(election) = self.previous_elections.get(&handle) {
            Some(election)
        } else {
            Self::not_found(handle);
            None
        }
    }

    fn get_mut(&mut self, handle: MetaElectionHandle) -> Option<&mut MetaElection> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&mut self.current_election)
        } else if let Some(election) = self.previous_elections.get_mut(&handle) {
            Some(election)
        } else {
            Self::not_found(handle);
            None
        }
    }

    fn not_found(handle: MetaElectionHandle) {
        log_or_panic!("Meta-election at {:?} not found", handle);
    }

    fn next_handle(&mut self) -> MetaElectionHandle {
        let handle = MetaElectionHandle(self.next_index);

        if self.next_index == usize::MAX - 1 {
            self.next_index = 0;
        } else {
            self.next_index += 1;
        }

        handle
    }
}

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) mod snapshot {
    use super::super::meta_event::snapshot::MetaEventSnapshot;
    use super::*;
    use gossip::{EventHash, Graph};
    use id::SecretId;
    use observation::snapshot::ObservationKeySnapshot;
    use peer_list::PeerList;

    #[serde(bound = "")]
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct MetaElectionsSnapshot<P: PublicId>(Vec<MetaElectionSnapshot<P>>);

    impl<P: PublicId> MetaElectionsSnapshot<P> {
        pub fn new<S>(
            meta_elections: &MetaElections,
            graph: &Graph<P>,
            peer_list: &PeerList<S>,
        ) -> Self
        where
            S: SecretId<PublicId = P>,
        {
            MetaElectionsSnapshot(
                meta_elections
                    .all()
                    .filter_map(|handle| meta_elections.get(handle))
                    .map(|meta_election| MetaElectionSnapshot::new(meta_election, graph, peer_list))
                    .collect(),
            )
        }
    }

    #[serde(bound = "")]
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct MetaElectionSnapshot<P: PublicId> {
        meta_events: BTreeMap<EventHash, MetaEventSnapshot<P>>,
        round_hashes: BTreeMap<P, Vec<RoundHash>>,
        all_voters: BTreeSet<P>,
        interesting_events: BTreeMap<P, Vec<EventHash>>,
        consensus_len: usize,
        payload_key: Option<ObservationKeySnapshot<P>>,
    }

    impl<P: PublicId> MetaElectionSnapshot<P> {
        pub fn new<S>(
            meta_election: &MetaElection,
            graph: &Graph<P>,
            peer_list: &PeerList<S>,
        ) -> Self
        where
            S: SecretId<PublicId = P>,
        {
            let meta_events = meta_election
                .meta_events
                .iter()
                .filter_map(|(index, meta_event)| {
                    graph
                        .get(*index)
                        .map(|event| *event.hash())
                        .map(|hash| (hash, MetaEventSnapshot::new(meta_event, peer_list)))
                })
                .collect();

            let interesting_events = meta_election
                .interesting_events
                .iter()
                .filter_map(|(peer_index, event_indices)| {
                    peer_list
                        .get(*peer_index)
                        .map(|peer| (peer.id(), event_indices))
                })
                .map(|(peer_id, indices)| {
                    let hashes = indices
                        .iter()
                        .filter_map(|index| graph.get(*index).map(|event| *event.hash()))
                        .collect();
                    (peer_id.clone(), hashes)
                })
                .collect();

            MetaElectionSnapshot {
                meta_events,
                round_hashes: meta_election
                    .round_hashes
                    .iter()
                    .filter_map(|(peer_index, hashes)| {
                        peer_list
                            .get(*peer_index)
                            .map(|peer| (peer.id().clone(), hashes.clone()))
                    })
                    .collect(),
                all_voters: meta_election
                    .all_voters
                    .iter()
                    .filter_map(|index| peer_list.get(*index).map(|peer| peer.id().clone()))
                    .collect(),
                interesting_events,
                consensus_len: meta_election.consensus_len,
                payload_key: meta_election
                    .payload_key
                    .as_ref()
                    .and_then(|key| ObservationKeySnapshot::new(key, peer_list)),
            }
        }
    }
}
