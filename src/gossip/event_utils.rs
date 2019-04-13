// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    id::SecretId,
    peer_list::{PeerIndex, PeerIndexMap, PeerList},
};
use fnv::FnvHashSet;
use itertools::{EitherOrBoth, Itertools};
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    iter,
};

// Map of forks created by single peer in the ancestry of the current event.
// Key is the index-by-creator of the forked events, value is a list of fork indices of the events
// that the current event is descendant of.
//
// ("fork index" is unique index within the fork set the event belongs to. "fork set" is the set of
// events having the same creator and index-by-creator).
//
// If there is an entry with two or more fork indices that means the current event is aware of the
// fork, because it has at least two sides of the fork in its ancestry.
//
// If there is only one fork index in the entry or the entry is missing completely, there can still
// be a fork, but we cannot prove it yet using just the ancestors of the current event.
pub(super) type ForkMap = BTreeMap<usize, IndexSet>;

// Immutable set of integer indices
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IndexSet(FnvHashSet<usize>);

impl IndexSet {
    pub fn new(index: usize) -> Self {
        IndexSet(iter::once(index).collect())
    }

    pub fn union(&self, other: &Self) -> Self {
        IndexSet(self.0.union(&other.0).cloned().collect())
    }

    pub fn insert(&self, index: usize) -> Self {
        let mut set = self.0.clone();
        let _ = set.insert(index);
        IndexSet(set)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, index: usize) -> bool {
        self.0.contains(&index)
    }

    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.0.is_disjoint(&other.0)
    }
}

impl Debug for IndexSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let values = self.0.iter().collect::<BTreeSet<_>>();
        write!(formatter, "{}", values.iter().format(", "))
    }
}

// Information about ancestor events.
#[derive(Clone, Debug, Default)]
pub(crate) struct AncestorInfo {
    // index-by-creator of the last event by the current peer that is ancestor of the current
    // event.
    pub last: usize,
    // Info about forks in the ancestry of the current event.
    pub forks: ForkMap,
}

impl AncestorInfo {
    pub fn new() -> Self {
        Self {
            last: 0,
            forks: ForkMap::new(),
        }
    }
}

pub(super) fn compute_ancestor_info<S: SecretId>(
    creator: PeerIndex,
    index_by_creator: usize,
    self_parent_info: Option<&PeerIndexMap<AncestorInfo>>,
    other_parent_info: Option<&PeerIndexMap<AncestorInfo>>,
    peer_list: &PeerList<S>,
) -> PeerIndexMap<AncestorInfo> {
    let mut result = match (self_parent_info, other_parent_info) {
        (Some(self_parent_info), Some(other_parent_info)) => {
            merge_ancestor_info_maps(self_parent_info, other_parent_info)
        }
        (Some(self_parent_info), None) => self_parent_info.clone(),
        (None, Some(other_parent_info)) => other_parent_info.clone(),
        (None, None) => PeerIndexMap::new(),
    };

    let info = result.entry(creator).or_insert_with(AncestorInfo::new);
    info.last = index_by_creator;

    let fork_index = peer_list.events_by_index(creator, index_by_creator).count();
    if fork_index > 0 {
        let _ = info
            .forks
            .insert(index_by_creator, IndexSet::new(fork_index));
    }

    result
}

fn merge_ancestor_info_maps(
    map0: &PeerIndexMap<AncestorInfo>,
    map1: &PeerIndexMap<AncestorInfo>,
) -> PeerIndexMap<AncestorInfo> {
    // Merge the two maps: if an entry exists in only one of the map, copy it over,
    // if it exists in both, merge them by calling `AncestorInfo::merge`.
    // We can use `merge_join_by` from `itertools` because `PeerIndexMap::iter` yields the entries
    // in ascending order.
    map0.iter()
        .merge_join_by(map1.iter(), |(peer_index0, _), (peer_index1, _)| {
            peer_index0.cmp(peer_index1)
        })
        .map(|either| match either {
            EitherOrBoth::Left((peer_index, info)) | EitherOrBoth::Right((peer_index, info)) => {
                (peer_index, info.clone())
            }
            EitherOrBoth::Both((peer_index, info0), (_, info1)) => {
                (peer_index, merge_ancestor_infos(info0, info1))
            }
        })
        .collect()
}

fn merge_ancestor_infos(lhs_info: &AncestorInfo, rhs_info: &AncestorInfo) -> AncestorInfo {
    AncestorInfo {
        last: cmp::max(lhs_info.last, rhs_info.last),
        forks: merge_fork_maps(lhs_info, rhs_info),
    }
}

fn merge_fork_maps(lhs_info: &AncestorInfo, rhs_info: &AncestorInfo) -> ForkMap {
    lhs_info
        .forks
        .iter()
        .merge_join_by(rhs_info.forks.iter(), |(key0, _), (key1, _)| key0.cmp(key1))
        .map(|either| match either {
            EitherOrBoth::Left((&index_by_creator, lhs_fork_set)) => (
                index_by_creator,
                merge_with_implicit_fork_set(lhs_fork_set, index_by_creator, rhs_info.last),
            ),
            EitherOrBoth::Right((&index_by_creator, rhs_fork_set)) => (
                index_by_creator,
                merge_with_implicit_fork_set(rhs_fork_set, index_by_creator, lhs_info.last),
            ),
            EitherOrBoth::Both((&index_by_creator, lhs_fork_set), (_, rhs_fork_set)) => {
                (index_by_creator, lhs_fork_set.union(rhs_fork_set))
            }
        })
        .collect()
}

fn merge_with_implicit_fork_set(
    forks: &IndexSet,
    index_by_creator: usize,
    last_ancestor: usize,
) -> IndexSet {
    if last_ancestor >= index_by_creator {
        // The second event is ancestor of the first event of the fork. Merge the fork set of the
        // first event with the implicit fork set [0].
        forks.insert(0)
    } else {
        // The second event is not an ancestor of any event of the fork - just clone the first fork
        // set.
        forks.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_fork_maps_of_events_that_are_not_descendants_of_any_fork() {
        // Merge C's fork maps of A1 and B1:
        //
        //       B1----+
        //       |     |
        // A1----------+
        // |     |     |
        // A0    B0    C0

        let a_info = AncestorInfo {
            last: 0,
            forks: btree_map![],
        };

        let b_info = AncestorInfo {
            last: 0,
            forks: btree_map![],
        };

        assert_eq!(merge_fork_maps(&a_info, &b_info), btree_map![])
    }

    #[test]
    fn merge_fork_maps_of_events_that_are_descendants_of_different_fork_sides() {
        //
        //       B1---------+
        //       |          |
        // A1---------+     |
        // |     |    |     |
        // |     |   C1,0  C1,1
        // |     |    |     |
        // |     |    +--+--+
        // |     |       |
        // A0    B0      C0

        let a_info = AncestorInfo {
            last: 1,
            forks: btree_map![],
        };

        let b_info = AncestorInfo {
            last: 1,
            forks: btree_map![1 => IndexSet::new(1)],
        };

        assert_eq!(
            merge_fork_maps(&a_info, &b_info),
            btree_map![1 => IndexSet::new(0).insert(1)]
        )
    }

    #[test]
    fn merge_fork_maps_of_events_that_are_descendants_of_same_fork_side() {
        //
        //       B1---------+
        //       |          |
        // A1---------------+
        // |     |          |
        // |     |   C1,0  C1,1
        // |     |    |     |
        // |     |    +--+--+
        // |     |       |
        // A0    B0      C0

        let a_info = AncestorInfo {
            last: 1,
            forks: btree_map![1 => IndexSet::new(1)],
        };

        let b_info = AncestorInfo {
            last: 1,
            forks: btree_map![1 => IndexSet::new(1)],
        };

        assert_eq!(
            merge_fork_maps(&a_info, &b_info),
            btree_map![1 => IndexSet::new(1)]
        )
    }

    #[test]
    fn merge_fork_maps_of_one_event_that_is_descendant_of_fork_and_another_that_isnt() {
        //
        //       B1---------+
        //       |          |
        //       |   C2,0  C2,1
        //       |    |     |
        //       |    +--+--+
        //       |       |
        // A1------------+
        // |     |       |
        // |     |       C1
        // |     |       |
        // A0    B0      C0

        let a_info = AncestorInfo {
            last: 1,
            forks: btree_map![],
        };

        let b_info = AncestorInfo {
            last: 2,
            forks: btree_map![2 => IndexSet::new(1)],
        };

        assert_eq!(
            merge_fork_maps(&a_info, &b_info),
            btree_map![2 => IndexSet::new(1)]
        )
    }
}
