// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    cause::Cause, event_context::EventContextRef, event_hash::EventHash, graph::EventIndex,
};
use crate::{
    error::Error,
    id::{PublicId, SecretId},
    network_event::NetworkEvent,
    observation::ObservationForStore,
    peer_list::PeerIndex,
    vote::{Vote, VoteKey},
};
use serde::{Deserialize, Serialize};

#[serde(bound(
    serialize = "V: Serialize, E: Serialize, P: Serialize",
    deserialize = "V: Deserialize<'de>, E: Deserialize<'de>, P: Deserialize<'de>"
))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub(super) struct Content<V, E, P> {
    // Identifier of the peer which created this `Event`.
    pub creator: P,
    // Whether it was created by receiving a gossip request, response or by being given a network
    // event to vote for.
    pub cause: Cause<V, E, P>,
}

impl<V, E, P> Content<V, E, P> {
    // Handle to sender's latest event if the `cause` is a request or response; otherwise `None`.
    pub fn other_parent(&self) -> Option<&E> {
        match self.cause {
            Cause::Request {
                ref other_parent, ..
            }
            | Cause::Response {
                ref other_parent, ..
            } => Some(other_parent),
            Cause::Requesting { .. } | Cause::Observation { .. } | Cause::Initial => None,
        }
    }

    // Handle to our latest event if the `cause` is a request, response or observation; otherwise
    // `None`.
    pub fn self_parent(&self) -> Option<&E> {
        match self.cause {
            Cause::Requesting {
                ref self_parent, ..
            }
            | Cause::Request {
                ref self_parent, ..
            }
            | Cause::Response {
                ref self_parent, ..
            }
            | Cause::Observation {
                ref self_parent, ..
            } => Some(self_parent),
            Cause::Initial => None,
        }
    }
}

impl<P: PublicId> Content<VoteKey<P>, EventIndex, PeerIndex> {
    pub(crate) fn unpack<T: NetworkEvent, S: SecretId<PublicId = P>>(
        packed_content: Content<Vote<T, P>, EventHash, P>,
        ctx: EventContextRef<'_, T, S>,
    ) -> Result<(Self, ObservationForStore<T, P>), Error> {
        let creator = ctx
            .peer_list
            .get_index(&packed_content.creator)
            .ok_or(Error::UnknownPeer)?;
        let (cause, observation_for_store) = Cause::unpack(packed_content.cause, creator, ctx)?;

        Ok((Self { creator, cause }, observation_for_store))
    }

    pub(crate) fn pack<T: NetworkEvent, S: SecretId<PublicId = P>>(
        &self,
        ctx: EventContextRef<'_, T, S>,
    ) -> Result<Content<Vote<T, P>, EventHash, P>, Error> {
        Ok(Content {
            creator: ctx
                .peer_list
                .get(self.creator)
                .map(|peer| peer.id().clone())
                .ok_or(Error::UnknownPeer)?,
            cause: self.cause.pack(ctx)?,
        })
    }
}
