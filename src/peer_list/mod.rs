// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod membership_list;
mod peer;
mod peer_index;
mod peer_state;

pub(crate) use self::membership_list::MembershipListChange;
pub(crate) use self::peer_index::{PeerIndex, PeerIndexMap, PeerIndexSet};
pub use self::peer_state::PeerState;
#[cfg(all(test, feature = "mock"))]
pub(crate) use self::snapshot::PeerListSnapshot;

#[cfg(feature = "malice-detection")]
use self::membership_list::MembershipListWithChanges;
use self::peer::Peer;
use error::Error;
use gossip::Event;
use hash::Hash;
use id::SecretId;
#[cfg(any(test, feature = "testing"))]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use std::collections::btree_map::{BTreeMap, Entry};
#[cfg(any(test, feature = "testing"))]
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::iter;

pub(crate) struct PeerList<S: SecretId> {
    our_id: S,
    our_peer: Peer<S::PublicId>,
    peers: Vec<Peer<S::PublicId>>,
    indices: BTreeMap<S::PublicId, PeerIndex>,
}

impl<S: SecretId> PeerList<S> {
    pub fn new(our_id: S) -> Self {
        let our_peer = Peer::new(our_id.public_id().clone(), PeerState::inactive());

        PeerList {
            our_id,
            our_peer,
            peers: Vec::new(),
            indices: BTreeMap::new(),
        }
    }

    pub fn our_id(&self) -> &S {
        &self.our_id
    }

    pub fn our_pub_id(&self) -> &S::PublicId {
        &self.our_id.public_id()
    }

    pub fn get_index(&self, peer_id: &S::PublicId) -> Option<PeerIndex> {
        if peer_id == self.our_id.public_id() {
            Some(PeerIndex::OUR)
        } else {
            self.indices.get(peer_id).cloned()
        }
    }

    pub fn contains(&self, peer_id: &S::PublicId) -> bool {
        peer_id == self.our_id.public_id() || self.indices.contains_key(peer_id)
    }

    pub fn get(&self, index: PeerIndex) -> Option<&Peer<S::PublicId>> {
        if index == PeerIndex::OUR {
            Some(&self.our_peer)
        } else {
            self.peers.get(index.0 - 1)
        }
    }

    pub fn get_known(&self, index: PeerIndex) -> Result<&Peer<S::PublicId>, Error> {
        self.get(index).ok_or_else(|| {
            log_or_panic!(
                "{:?} does not have peer with index {:?}",
                self.our_id.public_id(),
                index
            );
            Error::UnknownPeer
        })
    }

    fn get_known_mut(&mut self, index: PeerIndex) -> Option<&mut Peer<S::PublicId>> {
        if index == PeerIndex::OUR {
            Some(&mut self.our_peer)
        } else if let Some(peer) = self.peers.get_mut(index.0 - 1) {
            Some(peer)
        } else {
            log_or_panic!(
                "{:?} does not have peer with index {:?}",
                self.our_id.public_id(),
                index
            );
            None
        }
    }

    /// Returns an iterator of peers.
    pub fn iter(&self) -> impl Iterator<Item = (PeerIndex, &Peer<S::PublicId>)> {
        iter::once((PeerIndex::OUR, &self.our_peer)).chain(
            self.peers
                .iter()
                .enumerate()
                .map(|(index, peer)| (PeerIndex(index + 1), peer)),
        )
    }

    /// Returns an iterator of peers that can vote.
    pub fn voters(&self) -> impl Iterator<Item = (PeerIndex, &Peer<S::PublicId>)> {
        self.iter().filter(|(_, peer)| peer.state.can_vote())
    }

    /// Returns an iterator of peers that we can send gossip to.
    pub fn gossip_recipients<'a>(
        &'a self,
    ) -> impl Iterator<Item = (PeerIndex, &Peer<S::PublicId>)> + 'a {
        let iter = if self.our_peer.state.can_send() {
            let iter = self
                .iter()
                .skip(1)
                .filter(|(_, peer)| peer.state.can_vote() && peer.state.can_recv());
            Some(iter)
        } else {
            None
        };

        iter.into_iter().flat_map(|iter| iter)
    }

    /// Returns indices of all peers known to us.
    pub fn all_indices(&self) -> impl Iterator<Item = PeerIndex> {
        (0..=self.peers.len()).map(PeerIndex)
    }

    /// Return public ids of all peers.
    pub fn all_ids(&self) -> impl Iterator<Item = (PeerIndex, &S::PublicId)> {
        self.iter().map(|(index, peer)| (index, peer.id()))
    }

    /// Returns an unsorted map of peer index => Hash(peer_id).
    pub fn all_id_hashes(&self) -> impl Iterator<Item = (PeerIndex, &Hash)> {
        self.iter().map(|(index, peer)| (index, peer.id_hash()))
    }

    /// Returns indices of the peers that can vote.
    pub fn voter_indices<'a>(&'a self) -> impl Iterator<Item = PeerIndex> + 'a {
        self.voters().map(|(index, _)| index)
    }

    pub fn peer_state(&self, index: PeerIndex) -> PeerState {
        self.get(index)
            .map(|peer| peer.state)
            .unwrap_or_else(PeerState::inactive)
    }

    pub fn our_state(&self) -> PeerState {
        self.our_peer.state
    }

    /// Adds a peer in the given state into the map.
    pub fn add_peer(&mut self, peer_id: S::PublicId, state: PeerState) -> PeerIndex {
        if peer_id == *self.our_id.public_id() {
            log_or_panic!(
                "{:?} already has self in the peer list",
                self.our_id.public_id(),
            );

            return PeerIndex::OUR;
        }

        let (index, changed) = match self.indices.entry(peer_id) {
            Entry::Occupied(entry) => {
                log_or_panic!(
                    "{:?} already has {:?} in the peer list",
                    self.our_id.public_id(),
                    entry.key()
                );
                (*entry.get(), false)
            }
            Entry::Vacant(entry) => {
                let index = PeerIndex(self.peers.len() + 1);
                let peer = Peer::new(entry.key().clone(), state);

                self.peers.push(peer);
                let _ = entry.insert(index);

                (index, state.can_vote())
            }
        };

        if changed {
            self.record_our_membership_list_change(MembershipListChange::Add(index))
        }

        index
    }

    pub fn remove_peer(&mut self, index: PeerIndex) {
        if let Some(peer) = self.get_known_mut(index) {
            peer.state = PeerState::inactive();
        } else {
            return;
        };

        self.record_our_membership_list_change(MembershipListChange::Remove(index))
    }

    pub fn change_peer_state(&mut self, index: PeerIndex, state: PeerState) {
        let changed = if let Some(peer) = self.get_known_mut(index) {
            let could_vote = peer.state.can_vote();
            peer.state |= state;
            peer.state.can_vote() && !could_vote
        } else {
            false
        };

        if changed {
            self.record_our_membership_list_change(MembershipListChange::Add(index))
        }
    }

    /// Add `other_peer_id` to the membership list of the peer at `index`.
    /// If `index` refer to ourselves, this function does nothing to prevent redundancy (the `PeerList`
    /// itself is already our membership list).
    pub fn add_to_peer_membership_list(&mut self, index: PeerIndex, other_peer_id: &S::PublicId) {
        if let Some(other_index) = self.get_index(other_peer_id) {
            self.change_peer_membership_list(index, MembershipListChange::Add(other_index))
        }
    }

    /// Remove `other_peer_id` from the membership list of the peer at `index`.
    pub fn remove_from_peer_membership_list(
        &mut self,
        index: PeerIndex,
        other_peer_id: &S::PublicId,
    ) {
        if let Some(other_index) = self.get_index(other_peer_id) {
            self.change_peer_membership_list(index, MembershipListChange::Remove(other_index))
        }
    }

    pub fn change_peer_membership_list(&mut self, index: PeerIndex, change: MembershipListChange) {
        if index == PeerIndex::OUR {
            return;
        }

        if let Some(peer) = self.get_known_mut(index) {
            peer.change_membership_list(change)
        }
    }

    /// Initialise the membership list of the peer at `index`.
    pub fn initialise_peer_membership_list<I>(&mut self, index: PeerIndex, membership_list: I)
    where
        I: IntoIterator<Item = PeerIndex>,
    {
        // Do not populate our membership list as it would be redundant.
        if index == PeerIndex::OUR {
            return;
        }

        if let Some(peer) = self.get_known_mut(index) {
            let changes = membership_list
                .into_iter()
                .chain(iter::once(index))
                .map(MembershipListChange::Add);

            for change in changes {
                peer.change_membership_list(change)
            }
        }
    }

    /// Returns whether the membership list of the given peer is already initialised.
    pub fn is_peer_membership_list_initialised(&self, index: PeerIndex) -> bool {
        self.get(index)
            .map_or(false, |peer| !peer.membership_list().is_empty())
    }

    /// Same as `peer_membership_list_shapshot` except if there is a `Remove` at `event_index`,
    /// then that `Remove` won't be applied to the resulting list.
    #[cfg(feature = "malice-detection")]
    pub fn peer_membership_list_snapshot_excluding_last_remove(
        &self,
        peer_index: PeerIndex,
        event_index: usize,
    ) -> Option<PeerIndexSet> {
        let (mut list, changes) = self.peer_membership_list_and_changes(peer_index)?;

        for (index, change) in changes.iter().rev() {
            if *index == event_index && !change.is_remove() {
                continue;
            }
            if *index < event_index {
                break;
            }
            let _ = change.unapply(&mut list);
        }

        Some(list)
    }

    /// Returns the history of changes to the membership list of the given peer.
    pub fn peer_membership_list_changes(
        &self,
        index: PeerIndex,
    ) -> &[(usize, MembershipListChange)] {
        if let Some(peer) = self.get(index) {
            peer.membership_list_changes()
        } else {
            &[]
        }
    }

    /// Returns the index of the last event created by this peer. Returns `None` if cannot find.
    pub fn last_event(&self, peer_index: PeerIndex) -> Option<EventIndex> {
        self.get(peer_index)
            .and_then(|peer| peer.events().rev().next())
    }

    /// Returns the indices of the events at the given index-by-creator.
    pub fn events_by_index<'a>(
        &'a self,
        peer_index: PeerIndex,
        index_by_creator: usize,
    ) -> impl Iterator<Item = EventIndex> + 'a {
        self.get(peer_index)
            .into_iter()
            .flat_map(move |peer| peer.events_by_index(index_by_creator))
    }

    /// Returns the index of the last event gossiped to us by the given peer.
    pub fn last_gossiped_event_by(&self, peer_index: PeerIndex) -> Option<EventIndex> {
        self.get(peer_index)
            .and_then(|peer| peer.last_gossiped_event)
    }

    /// Record that the given peer gossiped to us the given event.
    pub fn record_gossiped_event_by(&mut self, index: PeerIndex, event_index: EventIndex) {
        if let Some(peer) = self.get_known_mut(index) {
            if peer
                .last_gossiped_event
                .map(|current| current < event_index)
                .unwrap_or(false)
            {
                peer.last_gossiped_event = Some(event_index)
            }
        }
    }

    pub fn confirm_can_add_event<T: NetworkEvent>(
        &self,
        event: &Event<T, S::PublicId>,
    ) -> Result<(), Error> {
        let peer = self.get(event.creator()).ok_or(Error::UnknownPeer)?;
        if event.creator() == PeerIndex::OUR || peer.state.can_send() {
            Ok(())
        } else {
            Err(Error::InvalidPeerState {
                required: PeerState::SEND,
                actual: peer.state,
            })
        }
    }

    /// Adds event created by the peer.
    pub fn add_event<T: NetworkEvent>(&mut self, event: IndexedEventRef<T, S::PublicId>) {
        if let Some(peer) = self.get_known_mut(event.creator()) {
            peer.add_event(event.index_by_creator(), event.event_index())
        }
    }

    /// Removes last event from its creator.
    #[cfg(test)]
    pub fn remove_last_event(&mut self, creator: PeerIndex) -> Option<EventIndex> {
        if let Some(peer) = self.get_known_mut(creator) {
            peer.remove_last_event()
        } else {
            None
        }
    }

    /// Indices of events of the given creator, in insertion order.
    pub fn peer_events<'a>(
        &'a self,
        peer_index: PeerIndex,
    ) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.get(peer_index)
            .into_iter()
            .flat_map(|peer| peer.events())
    }

    /// Hashes of our events in insertion order.
    #[cfg(any(test, feature = "malice-detection"))]
    pub fn our_events<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.peer_events(PeerIndex::OUR)
    }

    fn record_our_membership_list_change(&mut self, change: MembershipListChange) {
        self.our_peer.record_membership_list_change(change)
    }

    #[cfg(feature = "malice-detection")]
    fn peer_membership_list_and_changes(
        &self,
        index: PeerIndex,
    ) -> Option<MembershipListWithChanges> {
        let peer = self.get(index)?;
        let list = if index == PeerIndex::OUR {
            self.voter_indices().collect()
        } else {
            peer.membership_list().clone()
        };

        if list.is_empty() {
            None
        } else {
            Some((list, peer.membership_list_changes()))
        }
    }
}

impl<S: SecretId> Debug for PeerList<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(
            formatter,
            "PeerList{{ our_id: {:?}",
            self.our_id.public_id()
        )?;
        for peer in iter::once(&self.our_peer).chain(&self.peers) {
            writeln!(formatter, "    {:?},", peer)?;
        }
        write!(formatter, "}}")
    }
}

#[cfg(any(test, feature = "testing"))]
impl PeerList<PeerId> {
    // Creates a builder to build PeerList using the input parameters directly.
    pub(super) fn build_from_dot_input(
        our_id: PeerId,
        mut peer_data: BTreeMap<PeerId, (PeerState, BTreeSet<PeerId>)>,
    ) -> Builder {
        let (our_state, our_membership_list) = unwrap!(peer_data.remove(&our_id));
        let our_peer = Peer::new(our_id.public_id().clone(), our_state);

        let mut membership_lists = vec![our_membership_list];
        let mut peers = Vec::new();

        for (id, (state, membership_list)) in peer_data {
            peers.push(Peer::new(id, state));
            membership_lists.push(membership_list);
        }

        let indices: BTreeMap<_, _> = peers
            .iter()
            .enumerate()
            .map(|(index, peer)| (peer.id().clone(), PeerIndex(index + 1)))
            .collect();

        // Convert membership lists from sets of `PeerId` to sets of `PeerIndex`.
        let membership_lists = {
            let id_to_index = |id| {
                if id == *our_id.public_id() {
                    PeerIndex::OUR
                } else {
                    *unwrap!(indices.get(&id))
                }
            };

            membership_lists
                .into_iter()
                .enumerate()
                .map(|(index, id_list)| {
                    id_list
                        .into_iter()
                        .map(id_to_index)
                        .chain(iter::once(PeerIndex(index)))
                        .collect()
                })
                .collect()
        };

        Builder {
            peer_list: PeerList {
                our_id,
                our_peer,
                peers,
                indices,
            },
            membership_lists,
        }
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = (PeerIndex, &mut Peer<PeerId>)> {
        iter::once((PeerIndex::OUR, &mut self.our_peer)).chain(
            self.peers
                .iter_mut()
                .enumerate()
                .map(|(index, peer)| (PeerIndex(index + 1), peer)),
        )
    }
}

#[cfg(any(test, feature = "testing"))]
pub(crate) struct Builder {
    peer_list: PeerList<PeerId>,
    membership_lists: Vec<PeerIndexSet>,
}

#[cfg(any(test, feature = "testing"))]
impl Builder {
    pub fn peer_list(&self) -> &PeerList<PeerId> {
        &self.peer_list
    }

    pub fn finish(mut self, graph: &Graph<Transaction, PeerId>) -> PeerList<PeerId> {
        // Set peer events and apply the membership list changes.
        for ((index, peer), membership_list) in self.peer_list.iter_mut().zip(self.membership_lists)
        {
            peer.events = graph
                .iter()
                .filter(|event| event.creator() == index)
                .collect();

            for other_index in membership_list {
                peer.change_membership_list(MembershipListChange::Add(other_index));
            }
        }

        self.peer_list
    }
}

#[cfg(test)]
pub(crate) mod snapshot {
    use super::*;
    use gossip::EventHash;
    use id::PublicId;

    #[derive(Eq, PartialEq, Debug)]
    pub(crate) struct PeerListSnapshot<P: PublicId>(
        BTreeMap<P, (PeerState, BTreeSet<(usize, EventHash)>)>,
    );

    #[cfg(feature = "mock")]
    impl<P: PublicId> PeerListSnapshot<P> {
        pub fn new<T: NetworkEvent, S: SecretId<PublicId = P>>(
            peer_list: &PeerList<S>,
            graph: &Graph<T, P>,
        ) -> Self {
            PeerListSnapshot(
                peer_list
                    .iter()
                    .map(|(_, peer)| {
                        let events = peer
                            .indexed_events()
                            .filter_map(|(index_by_creator, event_index)| {
                                graph
                                    .get(event_index)
                                    .map(|event| (index_by_creator, *event.hash()))
                            })
                            .collect();

                        (peer.id().clone(), (peer.state, events))
                    })
                    .collect(),
            )
        }
    }
}
