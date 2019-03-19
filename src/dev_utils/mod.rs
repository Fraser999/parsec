// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// This is used to read a dumped dot file and rebuild the event graph and associated info.
#[cfg(any(test, feature = "testing"))]
mod dot_parser;
mod environment;
mod network;
mod peer;
mod peer_statuses;
#[cfg(feature = "testing")]
pub mod proptest;
#[cfg(any(all(test, feature = "mock"), feature = "testing"))]
mod record;
mod schedule;

#[cfg(all(test, feature = "mock", feature = "malice-detection"))]
pub(crate) use self::dot_parser::parse_dot_file_with_test_name;
#[cfg(test)]
pub(crate) use self::dot_parser::parse_test_dot_file;
#[cfg(all(test, feature = "mock"))]
pub(crate) use self::dot_parser::ParsedContents;
pub use self::environment::{Environment, RngChoice};
pub use self::network::{ConsensusError, Network};
pub use self::peer::{NetworkView, Peer, PeerStatus};
pub use self::peer_statuses::PeerStatuses;
#[cfg(any(all(test, feature = "mock"), feature = "testing"))]
pub use self::record::Record;
pub use self::schedule::*;

type Observation = super::observation::Observation<super::mock::Transaction, super::mock::PeerId>;
