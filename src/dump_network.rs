// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::Event;
use hash::Hash;
use id::{PublicId, SecretId};
use meta_vote::MetaVote;
use network_event::NetworkEvent;
use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

fn first_char<D: Debug>(id: &D) -> char {
    unwrap!(format!("{:?}", id).chars().next())
}

fn write_self_parents<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    node: &S::PublicId,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    events: &[&Event<T, S::PublicId>],
    positions: &BTreeMap<Hash, u64>,
) -> fmt::Result {
    writeln!(f, "    {:?} [style=invis]", node)?;
    for event in events {
        if let Some(self_parent) = event.self_parent() {
            let parent = if let Some(parent) = gossip_graph.get(self_parent) {
                parent
            } else {
                continue;
            };
            let event_pos = *positions.get(event.hash()).unwrap_or(&0);
            let self_parent_pos = *positions.get(parent.hash()).unwrap_or(&0);
            if event_pos <= (self_parent_pos + 1) {
                writeln!(f, "    \"{:?}\" -> \"{:?}\"", self_parent, event.hash())?
            } else {
                let gap = event_pos - self_parent_pos;
                writeln!(
                    f,
                    "    \"{:?}\" -> \"{:?}\" [minlen={}]",
                    self_parent,
                    event.hash(),
                    gap
                )?
            }
        } else {
            writeln!(f, "    {:?} -> \"{:?}\" [style=invis]", node, event.hash())?
        }
    }
    writeln!(f)
}

fn write_subgraph<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    node: &S::PublicId,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    events: &[&Event<T, S::PublicId>],
    positions: &BTreeMap<Hash, u64>,
) -> fmt::Result {
    writeln!(f, "  subgraph cluster_{:?} {{", node)?;
    writeln!(f, "    label={:?}", node)?;
    write_self_parents::<T, S>(f, node, gossip_graph, events, positions)?;
    writeln!(f)?;
    writeln!(f, "  }}")
}

fn write_other_parents<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    events: &[&Event<T, S::PublicId>],
) -> fmt::Result {
    // Write the communications between events
    for event in events {
        if let Some(other_event) = event.other_parent() {
            writeln!(
                f,
                "  \"{:?}\" -> \"{:?}\" [constraint=false]",
                other_event,
                event.hash()
            )?;
        }
    }
    writeln!(f)
}

fn write_nodes<S: SecretId>(f: &mut Formatter, nodes: &[S::PublicId]) -> fmt::Result {
    writeln!(f, "  {{")?;
    writeln!(f, "    rank=same")?;
    for node in nodes {
        writeln!(f, "    {:?} [style=filled, color=white]", node)?;
    }
    writeln!(f, "  }}")?;
    // Order the nodes alphabetically
    write!(f, "  ")?;
    let mut index = 0;
    for node in nodes {
        write!(f, "{:?}", node)?;
        if index < nodes.len() - 1 {
            write!(f, " -> ")?;
            index += 1;
        }
    }
    writeln!(f, " [style=invis]")
}

fn write_evaluates<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    meta_votes: &BTreeMap<Hash, BTreeMap<S::PublicId, MetaVote>>,
    initial_events: &[Hash],
) -> fmt::Result {
    for (event_hash, event) in gossip_graph.iter() {
        if let Some(event_meta_votes) = meta_votes.get(event_hash) {
            if event_meta_votes.len() == initial_events.len() {
                writeln!(f, " \"{:?}\" [shape=rectangle]", event.hash())?;

                write!(f, " \"{:?}\" ", event.hash())?;
                write!(
                    f,
                    " [label=\"{}_{}",
                    first_char(event.creator()),
                    event.index.unwrap_or(0)
                )?;

                write!(f, "\nRound: [")?;
                for (peer, meta_vote) in event_meta_votes.iter() {
                    write!(f, " {}:{} ", first_char(peer), meta_vote.round)?;
                }
                write!(f, "]")?;

                write!(f, "\nStep: [")?;
                for (peer, meta_vote) in event_meta_votes.iter() {
                    write!(f, " {}:{} ", first_char(peer), meta_vote.step)?;
                }
                write!(f, "]")?;

                write!(f, "\nEst: [")?;
                for (peer, meta_vote) in event_meta_votes.iter() {
                    write!(f, "{}:{{", first_char(peer))?;
                    for estimate in &meta_vote.estimates {
                        if *estimate {
                            write!(f, "t")?;
                        } else if meta_vote.estimates.len() > 1 {
                            write!(f, "f,")?;
                        } else {
                            write!(f, "f")?;
                        }
                    }
                    write!(f, "}} ")?;
                }
                write!(f, "]")?;

                write!(f, "\nBin: [")?;
                for (peer, meta_vote) in event_meta_votes.iter() {
                    write!(f, "{}:{{", first_char(peer))?;
                    for bool_value in &meta_vote.bin_values {
                        if *bool_value {
                            write!(f, "t")?;
                        } else if meta_vote.bin_values.len() > 1 {
                            write!(f, "f,")?;
                        } else {
                            write!(f, "f")?;
                        }
                    }
                    write!(f, "}} ")?;
                }
                write!(f, "]")?;

                write!(f, "\nAux: [")?;
                for (peer, meta_vote) in event_meta_votes.iter() {
                    if let Some(aux_vote) = meta_vote.aux_value {
                        if aux_vote {
                            write!(f, "{}:{{t}} ", first_char(peer))?;
                        } else {
                            write!(f, "{}:{{f}} ", first_char(peer))?;
                        }
                    }
                }
                write!(f, "]")?;

                write!(f, "\nDec: [")?;
                for (peer, meta_vote) in event_meta_votes.iter() {
                    if let Some(decision) = meta_vote.decision {
                        if decision {
                            write!(f, "{}:{{t}} ", first_char(peer))?;
                        } else {
                            write!(f, "{}:{{f}} ", first_char(peer))?;
                        }
                    }
                }
                write!(f, "]")?;

                writeln!(f, "\"]")?;
            } else {
                writeln!(
                    f,
                    " {:?} [label=\"{}_{}\"]",
                    event.hash(),
                    first_char(event.creator()),
                    event.index.unwrap_or(0)
                )?;
            }
        }
    }

    writeln!(f)
}

fn update_pos<T: NetworkEvent, S: SecretId>(
    positions: &mut BTreeMap<Hash, u64>,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
) {
    loop {
        let mut updated = false;
        for (hash, event) in gossip_graph.iter() {
            if !positions.contains_key(hash) {
                let self_parent_pos = if let Some(self_parent_hash) = event.self_parent() {
                    if let Some(self_parent_pos) = positions.get(self_parent_hash) {
                        *self_parent_pos
                    } else {
                        continue;
                    }
                } else {
                    event.index.unwrap_or(0)
                };
                let other_parent_pos = if let Some(other_parent_hash) = event.other_parent() {
                    if let Some(other_parent_pos) = positions.get(other_parent_hash) {
                        *other_parent_pos
                    } else {
                        continue;
                    }
                } else {
                    event.index.unwrap_or(0)
                };
                let _ = positions.insert(*hash, cmp::max(self_parent_pos, other_parent_pos) + 1);
                updated = true;
                break;
            }
        }
        if !updated {
            break;
        }
    }
}

fn write_gossip_graph_dot<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    meta_votes: &BTreeMap<Hash, BTreeMap<S::PublicId, MetaVote>>,
    initial_events: &[Hash],
) -> fmt::Result {
    let mut nodes = Vec::new();
    for initial in initial_events {
        let initial_event = if let Some(initial_event) = gossip_graph.get(initial) {
            initial_event
        } else {
            continue;
        };
        nodes.push(initial_event.creator().clone());
    }

    let mut positions: BTreeMap<Hash, u64> = BTreeMap::new();
    update_pos::<T, S>(&mut positions, gossip_graph);

    writeln!(f, "digraph GossipGraph {{")?;
    writeln!(f, "  splines=false")?;
    writeln!(f, "  rankdir=BT")?;

    for node in &nodes {
        let mut events: Vec<&Event<T, S::PublicId>> = gossip_graph
            .values()
            .filter_map(|event| {
                if event.creator() == node {
                    Some(event)
                } else {
                    None
                }
            })
            .collect();
        events.sort_by_key(|event| event.index.unwrap_or(0));
        write_subgraph::<T, S>(f, node, gossip_graph, &events, &positions)?;
        write_other_parents::<T, S>(f, &events)?;
    }

    write_evaluates::<T, S>(f, gossip_graph, meta_votes, initial_events)?;

    write_nodes::<S>(f, &nodes)?;
    writeln!(f, "}}")
}

/// Output a graphviz of the gossip graph.
pub(crate) fn dump_gossip_graph<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    meta_votes: &BTreeMap<Hash, BTreeMap<S::PublicId, MetaVote>>,
) -> fmt::Result {
    let initial_events: Vec<Hash> = gossip_graph
        .iter()
        .filter_map(|(hash, event)| {
            if event.index.unwrap_or(0) == 0 {
                Some(*hash)
            } else {
                None
            }
        })
        .collect();
    write_gossip_graph_dot::<T, S>(f, gossip_graph, meta_votes, &initial_events)
}
