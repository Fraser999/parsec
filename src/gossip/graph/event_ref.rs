// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    super::{abstract_event::AbstractEventRef, event::Event},
    event_index::EventIndex,
};
use crate::{id::PublicId, observation::ObservationKey, peer_list::PeerIndex};
use std::{
    cmp::{Ord, Ordering, PartialOrd},
    ops::Deref,
};

/// Reference to `Event` together with its index.
#[derive(Clone, Debug)]
pub(crate) struct IndexedEventRef<'a, P: PublicId> {
    pub(super) index: EventIndex,
    pub(super) event: &'a Event<P>,
}

// Note: for some reason #[derive(Copy)] doesn't work.
impl<P: PublicId> Copy for IndexedEventRef<'_, P> {}

impl<'a, P: PublicId> IndexedEventRef<'a, P> {
    pub fn event_index(&self) -> EventIndex {
        self.index
    }

    pub fn topological_index(&self) -> usize {
        self.index.topological_index()
    }

    /// Returns reference to the inner `Event`. Note this is not the same as `Deref::deref`,
    /// because the lifetime is different ('a vs 'self).
    pub fn inner(&self) -> &'a Event<P> {
        self.event
    }
}

impl<P: PublicId> Deref for IndexedEventRef<'_, P> {
    type Target = Event<P>;

    fn deref(&self) -> &Self::Target {
        self.event
    }
}

impl<P: PublicId> AsRef<Event<P>> for IndexedEventRef<'_, P> {
    fn as_ref(&self) -> &Event<P> {
        self.event
    }
}

impl<P: PublicId> PartialEq for IndexedEventRef<'_, P> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<P: PublicId> Eq for IndexedEventRef<'_, P> {}

impl<P: PublicId> PartialOrd for IndexedEventRef<'_, P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

impl<P: PublicId> Ord for IndexedEventRef<'_, P> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index.cmp(&other.index)
    }
}

impl<'a, P: PublicId> AbstractEventRef<'a> for IndexedEventRef<'a, P> {
    fn payload_key(self) -> Option<&'a ObservationKey> {
        self.event.payload_key()
    }

    fn creator(self) -> PeerIndex {
        self.event.creator()
    }

    fn index_by_creator(self) -> usize {
        self.event.index_by_creator()
    }
}
