// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::{
    fmt::{self, Debug, Formatter},
    ops::{BitOr, BitOrAssign},
};

/// Peer state is a bitflag with these flags:
///
/// - `VOTE`: if enabled, the peer can vote, which means they are counted towards the supermajority.
/// - `SEND`: if enabled, the peer can send gossips. For us it means we can send gossips to others.
///           For others it means we can receive gossips from them.
/// - `RECV`: if enabled, the peer can receive gossips. For us, it means we can receive gossips from
///           others. For others it means we can send gossips to them.
///
/// If all three are enabled, the state is called `active`. If none is enabled, it's `inactive`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerState(u8);

impl PeerState {
    /// The peer is counted towards supermajority.
    pub const VOTE: Self = PeerState(0b0000_0001);
    /// The peer can send gossips.
    pub const SEND: Self = PeerState(0b0000_0010);
    /// The peer can receive gossips.
    pub const RECV: Self = PeerState(0b0000_0100);

    pub fn inactive() -> Self {
        PeerState(0)
    }

    pub fn active() -> Self {
        Self::VOTE | Self::SEND | Self::RECV
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn can_vote(self) -> bool {
        self.contains(Self::VOTE)
    }

    pub fn can_send(self) -> bool {
        self.contains(Self::SEND)
    }

    pub fn can_recv(self) -> bool {
        self.contains(Self::RECV)
    }
}

impl BitOr for PeerState {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        PeerState(self.0 | rhs.0)
    }
}

impl BitOrAssign for PeerState {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

impl Debug for PeerState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut separator = false;

        write!(f, "PeerState(")?;

        if self.contains(Self::VOTE) {
            separator = true;
            write!(f, "VOTE")?;
        }

        if self.contains(Self::SEND) {
            if separator {
                write!(f, "|")?;
            }
            separator = true;
            write!(f, "SEND")?;
        }

        if self.contains(Self::RECV) {
            if separator {
                write!(f, "|")?;
            }
            write!(f, "RECV")?;
        }

        write!(f, ")")
    }
}
