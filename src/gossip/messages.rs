// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{gossip::packed_event::PackedEvent, id::PublicId, network_event::NetworkEvent};
use serde::{Deserialize, Serialize};

/// A gossip request message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request<T: NetworkEvent, P: PublicId> {
    pub(crate) packed_events: Vec<PackedEvent<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> Request<T, P> {
    pub(crate) fn new(packed_events: Vec<PackedEvent<T, P>>) -> Self {
        Self { packed_events }
    }
}

/// A gossip response message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response<T: NetworkEvent, P: PublicId> {
    pub(crate) packed_events: Vec<PackedEvent<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> Response<T, P> {
    pub(crate) fn new(packed_events: Vec<PackedEvent<T, P>>) -> Self {
        Self { packed_events }
    }
}
