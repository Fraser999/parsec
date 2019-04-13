// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
pub(crate) use self::tests::EventContext;
use super::graph::Graph;
use crate::{
    id::SecretId,
    network_event::NetworkEvent,
    observation::{ConsensusMode, ObservationStore},
    peer_list::PeerList,
};

pub(crate) struct EventContextRef<'a, T: NetworkEvent, S: SecretId> {
    pub(crate) graph: &'a Graph<S::PublicId>,
    pub(crate) peer_list: &'a PeerList<S>,
    pub(crate) observations: &'a ObservationStore<T, S::PublicId>,
    pub(crate) consensus_mode: ConsensusMode,
}

// `#[derive(Clone)]` doesn't work here for some reason...
impl<T: NetworkEvent, S: SecretId> Clone for EventContextRef<'_, T, S> {
    fn clone(&self) -> Self {
        Self {
            graph: self.graph,
            peer_list: self.peer_list,
            observations: self.observations,
            consensus_mode: self.consensus_mode,
        }
    }
}

// ...neither does `#[derive(Copy)]`.
impl<T: NetworkEvent, S: SecretId> Copy for EventContextRef<'_, T, S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{PeerId, Transaction};

    pub(crate) struct EventContext {
        pub graph: Graph<PeerId>,
        pub peer_list: PeerList<PeerId>,
        pub observations: ObservationStore<Transaction, PeerId>,
        pub consensus_mode: ConsensusMode,
    }

    impl EventContext {
        pub fn new(our_id: PeerId) -> Self {
            let peer_list = PeerList::new(our_id);

            Self {
                graph: Graph::new(),
                peer_list,
                observations: ObservationStore::new(),
                consensus_mode: ConsensusMode::Supermajority,
            }
        }

        pub fn as_ref(&self) -> EventContextRef<'_, Transaction, PeerId> {
            EventContextRef {
                graph: &self.graph,
                peer_list: &self.peer_list,
                observations: &self.observations,
                consensus_mode: self.consensus_mode,
            }
        }
    }
}
