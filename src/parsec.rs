// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
use error::Error;
use gossip::{Event, Request, Response};
use hash::Hash;
use id::SecretId;
use peer_manager::PeerManager;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use vote::Vote;

pub struct Parsec<T: Serialize + DeserializeOwned + Debug, S: SecretId> {
    // Holding PeerInfo of other nodes.
    peer_manager: PeerManager<S>,
    // Gossip events created locally and received from other peers.
    events: BTreeMap<Hash, Event<T, S::PublicId>>,
    // The hash of every stable block already returned via `poll()`.
    polled_blocks: BTreeSet<Hash>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: Vec<Block<T, S::PublicId>>,
    // Strongly-seen votes for network events in `polled_blocks` which haven't already
    // been returned via `poll()` (i.e. as part of the stable block) or via `extra_votes()`
    // yet.
    extra_votes: BTreeMap<S::PublicId, Vec<Vote<T, S::PublicId>>>,
}

// TODO - remove
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
impl<T: Serialize + DeserializeOwned + Debug, S: SecretId> Parsec<T, S> {
    /// Create a new `Parsec` for a peer with the given ID and genesis peer IDs.
    pub fn new(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Result<Self, Error> {
        unimplemented!();
    }

    /// Add a vote for `network_event`.
    pub fn vote_for(&mut self, network_event: T) {
        unimplemented!();
    }

    /// Create a new message to be gossiped to a random peer.
    pub fn create_gossip(&self) -> Request<T, S::PublicId> {
        unimplemented!();
    }

    /// Handle a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>, Error> {
        unimplemented!();
    }

    /// Handle a received `Response` from `src` peer.  Returns `Err` if the response was not valid.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        unimplemented!();
    }

    /// Step the algorithm and return the next stable block, if any.
    pub fn poll(&mut self) -> Result<Option<Block<T, S::PublicId>>, Error> {
        unimplemented!();
    }

    /// Check if the given `network_event` has already been voted for by us.
    pub fn have_voted_for(&self, network_event: &T) -> bool {
        unimplemented!();
    }
}
