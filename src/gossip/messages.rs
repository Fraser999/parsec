// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::{Error, Result};
use gossip::event::Event;
use gossip::event_hash::EventHash;
use gossip::packed_event::PackedEvent;
use id::PublicId;
use network_event::NetworkEvent;
use std::collections::BTreeMap;

/// A gossip pre-request message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PreRequest<P: PublicId> {
    pub(crate) latest_indices: BTreeMap<P, usize>,
}

/// A gossip pre-response message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PreResponse<P: PublicId> {
    pub(crate) latest_indices: BTreeMap<P, usize>,
}

/// A gossip request message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request<T: NetworkEvent, P: PublicId> {
    pub(crate) packed_events: Vec<PackedEvent<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> Request<T, P> {
    pub(crate) fn new(events: Vec<&Event<T, P>>) -> Self {
        Self {
            packed_events: events.into_iter().map(Event::pack).collect(),
        }
    }

    pub(crate) fn hash_of_last_event_created_by(&self, src: &P) -> Result<Option<EventHash>> {
        hash_of_last_event_created_by(src, &self.packed_events)
    }
}

/// A gossip response message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response<T: NetworkEvent, P: PublicId> {
    pub(crate) packed_events: Vec<PackedEvent<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> Response<T, P> {
    pub(crate) fn new(events: Vec<&Event<T, P>>) -> Self {
        Self {
            packed_events: events.into_iter().map(Event::pack).collect(),
        }
    }

    pub(crate) fn hash_of_last_event_created_by(&self, src: &P) -> Result<Option<EventHash>> {
        hash_of_last_event_created_by(src, &self.packed_events)
    }
}

// Returns `Err(Error::InvalidMessage)` if `packed_events` is non-empty, but doesn't contain an
// event created by `src`.
fn hash_of_last_event_created_by<T: NetworkEvent, P: PublicId>(
    src: &P,
    packed_events: &[PackedEvent<T, P>],
) -> Result<Option<EventHash>> {
    if packed_events.is_empty() {
        return Ok(None);
    }
    packed_events
        .iter()
        .rev()
        .find(|packed_event| packed_event.content.creator == *src)
        .ok_or_else(|| Error::InvalidMessage)
        .map(|packed_event| Some(packed_event.compute_hash()))
}
