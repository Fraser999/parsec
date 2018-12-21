// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::super::event::Event;
use hash::Hash;
use id::PublicId;
use network_event::NetworkEvent;
use std::collections::BTreeMap;

/// Iterator over all ancestors of the given event (including itself) in reverse topological order.
pub(crate) fn ancestors<'a, T: NetworkEvent, P: PublicId>(
    graph: &'a BTreeMap<Hash, Event<T, P>>,
    event: &'a Event<T, P>,
) -> Ancestors<'a, T, P> {
    let mut queue = BTreeMap::new();
    let _ = queue.insert(event.topological_index(), event);

    Ancestors {
        graph,
        queue,
        visited: vec![false; event.topological_index() + 1],
    }
}

pub(crate) struct Ancestors<'a, T: NetworkEvent + 'a, P: PublicId + 'a> {
    graph: &'a BTreeMap<Hash, Event<T, P>>,
    queue: BTreeMap<usize, &'a Event<T, P>>,
    visited: Vec<bool>, // TODO: replace with bitset, for space efficiency
}

impl<'a, T: NetworkEvent, P: PublicId> Iterator for Ancestors<'a, T, P> {
    type Item = &'a Event<T, P>;

    fn next(&mut self) -> Option<Self::Item> {
        // This is a modified breadth-first search: Instead of using a simple queue to track the
        // events to visit next, we use a priority queue (implemented as a BTreeMap keyed by
        // `topological_index`) so the events are visited in reverse topological order (children
        // before parents). We also keep track of the events we already visited, to avoid returning
        // single event more than once.

        loop {
            let index = *self.queue.keys().rev().next()?;
            let event = self.queue.remove(&index)?;

            if self.visited[index] {
                continue;
            }
            self.visited[index] = true;

            if let Some(parent) = event.self_parent().and_then(|hash| self.graph.get(hash)) {
                let _ = self.queue.insert(parent.topological_index(), parent);
            }

            if let Some(parent) = event.other_parent().and_then(|hash| self.graph.get(hash)) {
                let _ = self.queue.insert(parent.topological_index(), parent);
            }

            return Some(event);
        }
    }
}

// #[cfg(test)]
// mod tests {
//     // use super::super::find_event_by_short_name;
//     use super::*;
//     use dev_utils::parse_test_dot_file;

//     #[test]
//     fn ancestors_iterator() {
//         // Generated with RNG seed: [174994228, 1445633118, 3041276290, 90293447].
//         let contents = parse_test_dot_file("carol.dot");
//         let graph = contents.events;

//         let event = unwrap!(find_event_by_short_name(graph.values(), "B_4"));

//         let expected = vec![
//             "B_4", "B_3", "D_2", "D_1", "D_0", "B_2", "B_1", "B_0", "A_1", "A_0",
//         ];

//         let mut actual_names = Vec::new();
//         let mut actual_indices = Vec::new();

//         for event in ancestors(&graph, event) {
//             actual_names.push(event.short_name());
//             actual_indices.push(event.topological_index());
//         }

//         assert_eq!(actual_names, expected);

//         // Assert the events are yielded in reverse topological order.
//         let mut sorted_indices = actual_indices.clone();
//         sorted_indices.sort_by(|a, b| b.cmp(a));

//         assert_eq!(actual_indices, sorted_indices);
//     }
// }
