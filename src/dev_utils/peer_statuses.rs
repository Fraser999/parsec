// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::PeerStatus;
use crate::mock::PeerId;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use unwrap::unwrap;

pub struct PeerStatuses {
    statuses: BTreeMap<PeerId, PeerStatus>,
}

impl PeerStatuses {
    /// Creates a new `PeerStatuses` struct with the given active peers.
    pub fn new(names: &BTreeSet<PeerId>) -> PeerStatuses {
        PeerStatuses {
            statuses: names
                .iter()
                .map(|x| (x.clone(), PeerStatus::Active))
                .collect(),
        }
    }

    fn peers_by_status<F: Fn(&PeerStatus) -> bool>(
        &self,
        f: F,
    ) -> impl Iterator<Item = (&PeerId, &PeerStatus)> {
        self.statuses.iter().filter(move |&(_, status)| f(status))
    }

    fn choose_name_to_remove<R: Rng>(&self, rng: &mut R) -> PeerId {
        let names: Vec<&PeerId> = self
            .peers_by_status(|s| *s == PeerStatus::Active || *s == PeerStatus::Failed)
            .map(|(id, _)| id)
            .collect();
        (*unwrap!(rng.choose(&names))).clone()
    }

    fn choose_name_to_fail<R: Rng>(&self, rng: &mut R) -> PeerId {
        let names: Vec<&PeerId> = self
            .peers_by_status(|s| *s == PeerStatus::Active)
            .map(|(id, _)| id)
            .collect();
        (*unwrap!(rng.choose(&names))).clone()
    }

    /// Returns an iterator through all the peers.
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.statuses.keys()
    }

    fn num_active_peers(&self) -> usize {
        self.peers_by_status(|s| *s == PeerStatus::Active).count()
    }

    /// Returns an iterator through the list of active peers.
    pub fn active_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers_by_status(|s| *s == PeerStatus::Active)
            .map(|(id, _)| id)
    }

    /// Returns an iterator through the list of present peers (active or pending).
    pub fn present_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers_by_status(|s| *s == PeerStatus::Active || *s == PeerStatus::Pending)
            .map(|(id, _)| id)
    }

    /// Returns an iterator through the list of inactive peers (removed and failed).
    pub fn inactive_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers_by_status(|s| *s == PeerStatus::Removed || *s == PeerStatus::Failed)
            .map(|(id, _)| id)
    }

    fn num_failed_peers(&self) -> usize {
        self.peers_by_status(|s| *s == PeerStatus::Failed).count()
    }

    /// Adds an active peer.
    pub fn add_peer(&mut self, p: PeerId) {
        let _ = self.statuses.insert(p, PeerStatus::Active);
    }

    /// Randomly chooses a peer to remove.
    pub fn remove_random_peer<R: Rng>(&mut self, rng: &mut R, min_active: usize) -> Option<PeerId> {
        let name = self.choose_name_to_remove(rng);

        let mut active_peers = self.num_active_peers();
        let mut failed_peers = self.num_failed_peers();

        match self.statuses[&name] {
            PeerStatus::Active => active_peers -= 1,
            PeerStatus::Failed => failed_peers -= 1,
            _ => return None,
        }

        if 2 * failed_peers < active_peers && active_peers >= min_active {
            self.remove_peer(&name);
            Some(name)
        } else {
            None
        }
    }

    /// Remove the given peer.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        let status = unwrap!(self.statuses.get_mut(peer));
        *status = PeerStatus::Removed;
    }

    /// Randomly chooses a peer to fail.
    pub fn fail_random_peer<R: Rng>(&mut self, rng: &mut R, min_active: usize) -> Option<PeerId> {
        let name = self.choose_name_to_fail(rng);

        let active_peers = self.num_active_peers() - 1;
        let failed_peers = self.num_failed_peers() + 1;

        if 2 * failed_peers < active_peers && active_peers >= min_active {
            self.fail_peer(&name);
            Some(name)
        } else {
            None
        }
    }

    pub fn fail_peer(&mut self, peer: &PeerId) {
        let status = unwrap!(self.statuses.get_mut(peer));
        *status = PeerStatus::Failed;
    }
}

impl Into<BTreeMap<PeerId, PeerStatus>> for PeerStatuses {
    fn into(self) -> BTreeMap<PeerId, PeerStatus> {
        self.statuses
    }
}
