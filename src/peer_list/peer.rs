// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::peer_state::PeerState;
use crate::{
    gossip::{EventIndex, IndexedEventRef},
    hash::Hash,
    id::PublicId,
    serialise,
};
use itertools::Itertools;
use std::{
    fmt::{self, Debug, Formatter},
    iter::{self, FromIterator},
};

#[derive(Debug)]
pub(crate) struct Peer<P: PublicId> {
    id: P,
    id_hash: Hash,
    presence: Presence,
    pub(super) events: Events,
    pub(super) last_gossiped_event: Option<EventIndex>,
    // As a performance optimisation we keep track of which events we've cleared for Accomplice
    // accusations.
    #[cfg(feature = "malice-detection")]
    pub accomplice_event_checkpoint: Option<EventIndex>,
}

impl<P: PublicId> Peer<P> {
    pub(super) fn new(id: P, state: PeerState) -> Self {
        let id_hash = Hash::from(serialise(&id).as_slice());

        Self {
            id,
            id_hash,
            presence: Presence::Present(state),
            events: Events::new(),
            last_gossiped_event: None,
            #[cfg(feature = "malice-detection")]
            accomplice_event_checkpoint: None,
        }
    }

    pub fn id(&self) -> &P {
        &self.id
    }

    pub fn id_hash(&self) -> &Hash {
        &self.id_hash
    }

    pub fn state(&self) -> PeerState {
        match self.presence {
            Presence::Present(state) => state,
            Presence::Removed(_) => PeerState::inactive(),
        }
    }

    pub(super) fn change_state(&mut self, new_state: PeerState) {
        if let Presence::Present(ref mut old_state) = self.presence {
            *old_state |= new_state;
        }
    }

    pub(super) fn set_removed(&mut self, deciding_event_index: EventIndex) {
        self.presence = Presence::Removed(deciding_event_index)
    }

    pub fn events<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.events.iter()
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn indexed_events<'a>(
        &'a self,
    ) -> impl DoubleEndedIterator<Item = (usize, EventIndex)> + 'a {
        self.events.indexed()
    }

    pub fn events_by_index<'a>(&'a self, index: usize) -> impl Iterator<Item = EventIndex> + 'a {
        self.events.by_index(index)
    }

    pub fn removal_event(&self) -> Option<EventIndex> {
        match self.presence {
            Presence::Present(_) => None,
            Presence::Removed(event_index) => Some(event_index),
        }
    }

    pub(super) fn add_event(&mut self, index_by_creator: usize, event_index: EventIndex) {
        self.events.add(index_by_creator, event_index);
    }

    #[cfg(any(all(test, feature = "mock"), feature = "testing"))]
    pub(super) fn remove_last_event(&mut self) -> Option<EventIndex> {
        self.events.remove_last()
    }
}

#[derive(Debug)]
enum Presence {
    Present(PeerState),
    // Contains the index of the event at which we reached the consensus on the removal.
    Removed(EventIndex),
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

    #[cfg(any(all(test, feature = "mock"), feature = "testing"))]
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
        self.0.iter().flat_map(Slot::iter)
    }

    #[cfg(all(test, feature = "mock"))]
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
            .flat_map(Slot::iter)
    }
}

impl<'a, P> FromIterator<IndexedEventRef<'a, P>> for Events
where
    P: PublicId + 'a,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = IndexedEventRef<'a, P>>,
    {
        let mut events = Self::new();
        for event in iter {
            events.add(event.index_by_creator(), event.event_index());
        }

        events
    }
}

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

impl Debug for Slot {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.iter().format(", "))
    }
}
