// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::membership_list::MembershipListChange;
use super::peer_index::PeerIndexSet;
use super::peer_state::PeerState;
use hash::Hash;
use id::PublicId;
use network_event::NetworkEvent;
use serialise;
use std::iter::{self, FromIterator};

#[derive(Debug)]
pub(crate) struct Peer<P: PublicId> {
    id: P,
    id_hash: Hash,
    pub(super) state: PeerState,
    pub(super) events: Events,
    pub(super) last_gossiped_event: Option<EventIndex>,
    membership_list: PeerIndexSet,
    membership_list_changes: Vec<(usize, MembershipListChange)>,
}

impl<P: PublicId> Peer<P> {
    pub(super) fn new(id: P, state: PeerState) -> Self {
        let id_hash = Hash::from(serialise(&id).as_slice());

        Self {
            id,
            id_hash,
            state,
            events: Events::new(),
            last_gossiped_event: None,
            membership_list: PeerIndexSet::default(),
            membership_list_changes: Vec::new(),
        }
    }

    pub fn id(&self) -> &P {
        &self.id
    }

    pub fn id_hash(&self) -> &Hash {
        &self.id_hash
    }

    pub fn state(&self) -> PeerState {
        self.state
    }

    pub fn events<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.events.iter()
    }

    #[cfg(test)]
    pub fn indexed_events<'a>(
        &'a self,
    ) -> impl DoubleEndedIterator<Item = (usize, EventIndex)> + 'a {
        self.events.indexed()
    }

    pub fn events_by_index<'a>(&'a self, index: usize) -> impl Iterator<Item = EventIndex> + 'a {
        self.events.by_index(index)
    }

    pub(super) fn add_event(&mut self, index_by_creator: usize, event_index: EventIndex) {
        self.events.add(index_by_creator, event_index);
    }

    #[cfg(test)]
    pub(super) fn remove_last_event(&mut self) -> Option<EventIndex> {
        self.events.remove_last()
    }

    pub(super) fn change_membership_list(&mut self, change: MembershipListChange) {
        if change.apply(&mut self.membership_list) {
            self.record_membership_list_change(change);
        }
    }

    pub(super) fn record_membership_list_change(&mut self, change: MembershipListChange) {
        let index = self
            .events
            .indexed()
            .rev()
            .next()
            .map(|(index, _)| index)
            .unwrap_or(0);
        self.membership_list_changes.push((index, change));
    }

    pub(crate) fn membership_list(&self) -> &PeerIndexSet {
        &self.membership_list
    }

    pub(super) fn membership_list_changes(&self) -> &[(usize, MembershipListChange)] {
        &self.membership_list_changes
    }
}

#[derive(Debug)]
pub(super) struct Events(Vec<Slot>);

impl Events {
    fn new() -> Self {
        Events(Vec::new())
    }

    fn add(&mut self, index_by_creator: usize, event_index: EventIndex) {
        if let Some(slot) = self.0.get_mut(index_by_creator) {
            slot.add(event_index);
            return;
        }

        if index_by_creator != self.0.len() {
            log_or_panic!("Peer events must be added sequentially");
        }

        self.0.push(Slot::new(event_index))
    }

    #[cfg(test)]
    fn remove_last(&mut self) -> Option<EventIndex> {
        if let Some(slot) = self.0.last_mut() {
            if let Some(index) = slot.rest.pop() {
                return Some(index);
            }
        } else {
            return None;
        }

        self.0.pop().map(|slot| slot.first)
    }

    fn iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.0.iter().flat_map(|slot| slot.iter())
    }

    fn indexed<'a>(&'a self) -> impl DoubleEndedIterator<Item = (usize, EventIndex)> + 'a {
        self.0
            .iter()
            .enumerate()
            .flat_map(|(index_by_creator, slot)| {
                slot.iter()
                    .map(move |event_index| (index_by_creator, event_index))
            })
    }

    fn by_index<'a>(&'a self, index_by_creator: usize) -> impl Iterator<Item = EventIndex> + 'a {
        self.0
            .get(index_by_creator)
            .into_iter()
            .flat_map(|slot| slot.iter())
    }
}

impl<'a, T, P> FromIterator<IndexedEventRef<'a, T, P>> for Events
where
    T: NetworkEvent + 'a,
    P: PublicId + 'a,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = IndexedEventRef<'a, T, P>>,
    {
        let mut events = Self::new();
        for event in iter {
            events.add(event.index_by_creator(), event.event_index());
        }

        events
    }
}

#[derive(Debug)]
struct Slot {
    first: EventIndex,
    rest: Vec<EventIndex>,
}

impl Slot {
    fn new(event_index: EventIndex) -> Self {
        Self {
            first: event_index,
            rest: Vec::new(),
        }
    }

    fn add(&mut self, event_index: EventIndex) {
        self.rest.push(event_index)
    }

    fn iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        iter::once(self.first).chain(self.rest.iter().cloned())
    }
}
