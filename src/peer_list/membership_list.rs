// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use id::PublicId;
use std::collections::HashSet;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub(crate) enum MembershipListChange<P: PublicId> {
    Add(Rc<P>),
    Remove(Rc<P>),
}

impl<P: PublicId> MembershipListChange<P> {
    pub(super) fn apply(&self, peers: &mut HashSet<Rc<P>>) -> bool {
        match *self {
            MembershipListChange::Add(id) => peers.insert(id),
            MembershipListChange::Remove(id) => peers.remove(&id),
        }
    }

    #[cfg(feature = "malice-detection")]
    pub(super) fn revert(&self, peers: &mut HashSet<Rc<P>>) -> bool {
        match *self {
            MembershipListChange::Add(id) => peers.remove(&id),
            MembershipListChange::Remove(id) => peers.insert(id),
        }
    }

    #[cfg(feature = "malice-detection")]
    pub(super) fn is_remove(&self) -> bool {
        match *self {
            MembershipListChange::Remove(_) => true,
            MembershipListChange::Add(_) => false,
        }
    }
}

#[cfg(feature = "malice-detection")]
pub(super) type MembershipListWithChanges<'a, P: PublicId> =
    (HashSet<Rc<P>>, &'a [(usize, MembershipListChange<P>)]);
