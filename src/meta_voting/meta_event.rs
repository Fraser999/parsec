// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_elections::MetaElectionHandle;
use super::meta_vote::MetaVote;
use gossip::IndexedEventRef;
use id::PublicId;
use observation::ObservationKey;

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct MetaEvent {
    // The set of peers for which this event can strongly-see an event by that peer which carries a
    // valid block.  If there are a supermajority of peers here, this event is an "observer".
    pub observees: PeerIndexSet,
    // Hashes of payloads of all the votes deemed interesting by this event.
    pub interesting_content: Vec<ObservationKey>,
    pub meta_votes: PeerIndexMap<Vec<MetaVote>>,
}

impl MetaEvent {
    pub fn build<P: PublicId>(
        election: MetaElectionHandle,
        event: IndexedEventRef<P>,
    ) -> MetaEventBuilder<P> {
        MetaEventBuilder {
            election,
            event,
            meta_event: MetaEvent {
                observees: PeerIndexSet::default(),
                interesting_content: Vec::new(),
                meta_votes: PeerIndexMap::default(),
            },
        }
    }
}

pub(crate) struct MetaEventBuilder<'a, P: PublicId + 'a> {
    election: MetaElectionHandle,
    event: IndexedEventRef<'a, P>,
    meta_event: MetaEvent,
}

impl<'a, P: PublicId + 'a> MetaEventBuilder<'a, P> {
    pub fn election(&self) -> MetaElectionHandle {
        self.election
    }

    pub fn event(&self) -> IndexedEventRef<'a, P> {
        self.event
    }

    pub fn observee_count(&self) -> usize {
        self.meta_event.observees.len()
    }

    pub fn has_observee(&self, peer_index: PeerIndex) -> bool {
        self.meta_event.observees.contains(&peer_index)
    }

    pub fn set_observees(&mut self, observees: PeerIndexSet) {
        self.meta_event.observees = observees;
    }

    pub fn set_interesting_content(&mut self, content: Vec<ObservationKey>) {
        self.meta_event.interesting_content = content;
    }

    pub fn add_meta_votes(&mut self, peer_index: PeerIndex, votes: Vec<MetaVote>) {
        let _ = self.meta_event.meta_votes.insert(peer_index, votes);
    }

    pub fn finish(self) -> MetaEvent {
        self.meta_event
    }
}

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) mod snapshot {
    use super::*;
    use id::SecretId;
    use observation::snapshot::ObservationKeySnapshot;
    use peer_list::PeerList;
    use std::collections::{BTreeMap, BTreeSet};

    #[serde(bound = "")]
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct MetaEventSnapshot<P: PublicId> {
        observees: BTreeSet<P>,
        interesting_content: Vec<ObservationKeySnapshot<P>>,
        meta_votes: BTreeMap<P, Vec<MetaVote>>,
    }

    impl<P: PublicId> MetaEventSnapshot<P> {
        pub fn new<S>(meta_event: &MetaEvent, peer_list: &PeerList<S>) -> Self
        where
            S: SecretId<PublicId = P>,
        {
            Self {
                observees: meta_event
                    .observees
                    .iter()
                    .filter_map(|index| peer_list.get(*index))
                    .map(|peer| peer.id().clone())
                    .collect(),
                interesting_content: meta_event
                    .interesting_content
                    .iter()
                    .filter_map(|key| ObservationKeySnapshot::new(key, peer_list))
                    .collect(),
                meta_votes: meta_event
                    .meta_votes
                    .iter()
                    .filter_map(|(peer_index, votes)| {
                        peer_list
                            .get(*peer_index)
                            .map(|peer| (peer.id().clone(), votes.clone()))
                    })
                    .collect(),
            }
        }
    }

}
