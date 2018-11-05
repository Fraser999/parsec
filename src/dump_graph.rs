// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::Event;
use hash::Hash;
use id::SecretId;
use meta_voting::MetaElections;
use network_event::NetworkEvent;
use peer_list::PeerList;
use std::collections::BTreeMap;

/// Use this to initialise the folder into which the dot files will be dumped.  This allows the
/// folder's path to be displayed at the start of a run, rather than at the arbitrary point when
/// the first node's first stable block is about to be returned.  No-op for case where `dump-graphs`
/// feature not enabled.
pub(crate) fn init() {
    #[cfg(feature = "dump-graphs")]
    detail::init()
}

/// This function will dump the graphs from the specified peer in dot format to a random folder in
/// the system's temp dir.  It will also try to create an SVG from each such dot file, but will not
/// fail or report failure if the SVG files can't be created.  The location of this folder will be
/// printed to stdout.  The function will never panic, and hence is suitable for use in creating
/// these files after a thread has already panicked, e.g. in the case of a test failure.  No-op for
/// case where `dump-graphs` feature not enabled.
#[cfg(feature = "dump-graphs")]
pub(crate) fn to_file<T: NetworkEvent, S: SecretId>(
    owner_id: &S::PublicId,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    meta_elections: &MetaElections<T, S::PublicId>,
    peer_list: &PeerList<S>,
) {
    detail::to_file(owner_id, gossip_graph, meta_elections, peer_list)
}
#[cfg(not(feature = "dump-graphs"))]
pub(crate) fn to_file<T: NetworkEvent, S: SecretId>(
    _: &S::PublicId,
    _: &BTreeMap<Hash, Event<T, S::PublicId>>,
    _: &MetaElections<T, S::PublicId>,
    _: &PeerList<S>,
) {
}

#[cfg(feature = "dump-graphs")]
pub use self::detail::DIR;

#[cfg(feature = "dump-graphs")]
mod detail {
    use gossip::Event;
    use hash::Hash;
    use id::{PublicId, SecretId};
    use meta_voting::{MetaElections, MetaEvent, MetaVotes};
    use network_event::NetworkEvent;
    use peer_list::PeerList;
    use rand::{self, Rng};
    use serialise;
    use std::cell::RefCell;
    use std::cmp;
    use std::collections::BTreeMap;
    use std::env;
    use std::fmt::{self, Debug};
    use std::fs::{self, File};
    use std::io::{self, BufWriter, Write};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;
    use vote::Vote;

    lazy_static! {
        static ref ROOT_DIR_PREFIX: PathBuf = { env::temp_dir().join("parsec_graphs") };
        static ref ROOT_DIR_SUFFIX: String = {
            rand::thread_rng()
                .gen_ascii_chars()
                .take(6)
                .collect::<String>()
        };
        static ref ROOT_DIR: PathBuf = { ROOT_DIR_PREFIX.join(&*ROOT_DIR_SUFFIX) };
    }

    thread_local!(/// The directory to which test data is dumped
    pub static DIR: PathBuf = {
        let dir = match thread::current().name() {
            Some(thread_name) if thread_name != "main" => {
                ROOT_DIR.join(thread_name.replace("::", "_"))
            }
            _ => ROOT_DIR.clone(),
        };
        if let Err(error) = fs::create_dir_all(&dir) {
            println!(
                "Failed to create folder {} for dot files: {:?}",
                dir.display(),
                error
            );
        } else {
            println!("Writing dot files in {}", dir.display());
        }
        dir
    };);

    thread_local!(static DUMP_COUNTS: RefCell<BTreeMap<String, usize>> =
        RefCell::new(BTreeMap::new()));

    fn catch_dump<T: NetworkEvent, P: PublicId>(
        mut file_path: PathBuf,
        gossip_graph: &BTreeMap<Hash, Event<T, P>>,
        meta_elections: &MetaElections<T, P>,
    ) {
        if let Some("dev_utils::dot_parser::tests::dot_parser") = thread::current().name() {
            let dumped_info = serialise(&(gossip_graph, meta_elections));
            assert!(file_path.set_extension("core"));
            let mut file = unwrap!(File::create(&file_path));
            unwrap!(file.write_all(&dumped_info));
        }
    }

    pub(crate) fn init() {
        DIR.with(|_| ());
    }

    pub(crate) fn to_file<T: NetworkEvent, S: SecretId>(
        owner_id: &S::PublicId,
        gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
        meta_elections: &MetaElections<T, S::PublicId>,
        peer_list: &PeerList<S>,
    ) {
        let id = format!("{:?}", owner_id);
        let call_count = DUMP_COUNTS.with(|counts| {
            let mut borrowed_counts = counts.borrow_mut();
            let count = borrowed_counts.entry(id.clone()).or_insert(0);
            *count += 1;
            *count
        });
        let file_path = DIR.with(|dir| dir.join(format!("{}-{:03}.dot", id, call_count)));
        catch_dump(file_path.clone(), gossip_graph, meta_elections);

        match DotWriter::new(&file_path, gossip_graph, meta_elections, peer_list) {
            Ok(mut dot_writer) => {
                if let Err(error) = dot_writer.write() {
                    println!("Error writing to {:?}: {:?}", file_path, error);
                }
            }
            Err(error) => println!("Failed to create {:?}: {:?}", file_path, error),
        }

        // Try to generate an SVG file from the dot file, but we don't care about failure here.
        if let Ok(mut child) = Command::new("dot")
            .args(&["-Tsvg", file_path.to_string_lossy().as_ref(), "-O"])
            .spawn()
        {
            let _ = child.wait();
        }

        // Create symlink so it's easier to find the latest graphs.
        let _ = force_symlink_dir(&*ROOT_DIR, ROOT_DIR_PREFIX.join("latest"));
    }

    fn parent_pos(
        index: u64,
        parent_hash: Option<&Hash>,
        positions: &BTreeMap<Hash, u64>,
    ) -> Option<u64> {
        if let Some(parent_hash) = parent_hash {
            if let Some(parent_pos) = positions.get(parent_hash) {
                Some(*parent_pos)
            } else if *parent_hash == Hash::ZERO {
                Some(index)
            } else {
                None
            }
        } else {
            Some(index)
        }
    }

    fn force_symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
        use std::io::ErrorKind;
        // Try to overwrite the destination if it exists, but only if it is a symlink, to prevent
        // accidental data loss.
        match fs::symlink_metadata(&dst) {
            Err(ref error) if error.kind() == ErrorKind::NotFound => (),
            Err(error) => return Err(error),
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    let _ = remove_symlink_dir(&dst);
                }
            }
        }

        symlink_dir(src, dst)
    }

    #[cfg(unix)]
    fn symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
        use std::os::unix::fs::symlink;
        symlink(src, dst)
    }

    #[cfg(unix)]
    fn remove_symlink_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
        fs::remove_file(path)
    }

    #[cfg(windows)]
    fn symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
        use std::os::windows::fs::symlink_dir;
        symlink_dir(src, dst)
    }

    #[cfg(windows)]
    fn remove_symlink_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
        fs::remove_dir(path)
    }

    fn first_char<D: Debug>(id: &D) -> Option<char> {
        format!("{:?}", id).chars().next()
    }

    fn dump_meta_votes<P: PublicId>(meta_votes: &MetaVotes<P>, comment: bool) -> Vec<String> {
        let mut lines = vec![];
        if comment {
            lines.push("  stage est bin aux dec".to_string());
        } else {
            lines.push(
                "<tr><td></td><td width=\"50\">stage</td>\
                 <td width=\"30\">est</td>\
                 <td width=\"30\">bin</td>\
                 <td width=\"30\">aux</td>\
                 <td width=\"30\">dec</td></tr>"
                    .to_string(),
            );
        }
        for (peer, meta_votes) in meta_votes {
            let mut prefix = format!("{}: ", first_char(peer).unwrap_or('?'));
            for mv in meta_votes {
                let est = mv.estimates.as_short_string();
                let bin = mv.bin_values.as_short_string();
                let aux = match mv.aux_value {
                    None => "-",
                    Some(true) => "t",
                    Some(false) => "f",
                };
                let dec = match mv.decision {
                    None => "-",
                    Some(true) => "t",
                    Some(false) => "f",
                };
                let line = if comment {
                    format!(
                        "{}{}/{:?}   {}   {}   {}   {} ",
                        prefix, mv.round, mv.step, est, bin, aux, dec
                    )
                } else {
                    format!(
                        "<tr><td>{}</td><td>{}/{:?}</td><td>{}</td>\
                         <td>{}</td><td>{}</td><td>{}</td></tr>",
                        prefix, mv.round, mv.step, est, bin, aux, dec
                    )
                };
                // we want only the first line to have the prefix
                // wrapping in an `if` avoids multiple allocations
                if prefix != "   " {
                    prefix = "   ".to_string();
                }
                lines.push(line);
            }
        }
        lines
    }

    struct DotWriter<'a, T: NetworkEvent + 'a, S: SecretId + 'a> {
        file: BufWriter<File>,
        gossip_graph: &'a BTreeMap<Hash, Event<T, S::PublicId>>,
        meta_elections: &'a MetaElections<T, S::PublicId>,
        peer_list: &'a PeerList<S>,
        indent: usize,
    }

    impl<'a, T: NetworkEvent + 'a, S: SecretId + 'a> DotWriter<'a, T, S> {
        const COMMENT: &'static str = "/// ";

        fn new(
            file_path: &Path,
            gossip_graph: &'a BTreeMap<Hash, Event<T, S::PublicId>>,
            meta_elections: &'a MetaElections<T, S::PublicId>,
            peer_list: &'a PeerList<S>,
        ) -> io::Result<Self> {
            File::create(&file_path).map(|file| DotWriter {
                file: BufWriter::new(file),
                gossip_graph,
                meta_elections,
                peer_list,
                indent: 0,
            })
        }

        fn indentation(&self) -> String {
            " ".repeat(self.indent)
        }

        fn indent(&mut self) {
            self.indent += 2;
        }

        fn dedent(&mut self) {
            self.indent -= 2;
        }

        fn hash_to_short_name(&self, hash: &Hash) -> Option<String> {
            self.gossip_graph.get(hash).map(|event| event.short_name())
        }

        fn writeln(&mut self, args: fmt::Arguments) -> io::Result<()> {
            writeln!(self.file, "{}", args)
        }

        fn write(&mut self) -> io::Result<()> {
            self.write_peer_list()?;

            self.writeln(format_args!("digraph GossipGraph {{"))?;
            self.writeln(format_args!("  splines=false"))?;
            self.writeln(format_args!("  rankdir=BT\n"))?;

            let positions = self.calculate_positions();
            for peer_id in self.peer_list.all_ids() {
                self.write_subgraph(peer_id, &positions)?;
                self.write_other_parents(peer_id)?;
            }

            self.write_peers()?;

            self.writeln(format_args!("/// ===== details of events ====="))?;
            for peer_id in self.peer_list.all_ids() {
                self.write_event_details(peer_id)?;
            }
            self.writeln(format_args!("}}\n"))?;

            self.write_meta_elections()?;

            Ok(())
        }

        fn write_peer_list(&mut self) -> io::Result<()> {
            let indent = self.indentation();
            self.writeln(format_args!(
                "{}{}our_id: {:?}",
                Self::COMMENT,
                indent,
                self.peer_list.our_id().public_id()
            ))?;
            self.writeln(format_args!("{}{}peer_list: {{", Self::COMMENT, indent,))?;
            self.indent();
            let indent = self.indentation();
            for (peer_id, peer) in self.peer_list.iter() {
                self.writeln(format_args!(
                    "{}{}{:?}; {:?}; peers: {:?}",
                    Self::COMMENT,
                    indent,
                    peer_id,
                    peer.state(),
                    peer.membership_list(),
                ))?;
            }
            self.dedent();
            let indent = self.indentation();
            self.writeln(format_args!("{}{}}}", Self::COMMENT, indent))
        }

        fn calculate_positions(&self) -> BTreeMap<Hash, u64> {
            let mut positions = BTreeMap::new();
            while positions.len() < self.gossip_graph.len() {
                for (hash, event) in self.gossip_graph.iter() {
                    if !positions.contains_key(hash) {
                        let self_parent_pos = if let Some(position) =
                            parent_pos(event.index(), event.self_parent(), &positions)
                        {
                            position
                        } else {
                            continue;
                        };
                        let other_parent_pos = if let Some(position) =
                            parent_pos(event.index(), event.other_parent(), &positions)
                        {
                            position
                        } else {
                            continue;
                        };
                        let _ = positions
                            .insert(*hash, cmp::max(self_parent_pos, other_parent_pos) + 1);
                        break;
                    }
                }
            }
            positions
        }

        fn write_subgraph(
            &mut self,
            peer_id: &S::PublicId,
            positions: &BTreeMap<Hash, u64>,
        ) -> io::Result<()> {
            self.writeln(format_args!("  style=invis"))?;
            self.writeln(format_args!("  subgraph cluster_{:?} {{", peer_id))?;
            self.writeln(format_args!("    label={:?}", peer_id))?;
            self.writeln(format_args!("    {:?} [style=invis]", peer_id))?;
            self.write_self_parents(peer_id, positions)?;
            self.writeln(format_args!("  }}"))
        }

        fn write_self_parents(
            &mut self,
            peer_id: &S::PublicId,
            positions: &BTreeMap<Hash, u64>,
        ) -> io::Result<()> {
            let mut lines = vec![];
            for event in self
                .peer_list
                .peer_events(peer_id)
                .filter_map(|hash| self.gossip_graph.get(hash))
            {
                let (before_arrow, suffix) = match event.self_parent() {
                    None => (format!("\"{:?}\"", peer_id), "[style=invis]".to_string()),
                    Some(parent_hash) => {
                        let event_pos = *positions.get(event.hash()).unwrap_or(&0);
                        let parent_pos = *positions.get(parent_hash).unwrap_or(&0);
                        let minlen = if event_pos > parent_pos {
                            event_pos - parent_pos
                        } else {
                            1
                        };
                        (
                            format!("\"{}\"", unwrap!(self.hash_to_short_name(parent_hash))),
                            format!("[minlen={}]", minlen),
                        )
                    }
                };
                lines.push(format!(
                    "    {} -> \"{}\" {}",
                    before_arrow,
                    event.short_name(),
                    suffix
                ));
            }
            if !lines.is_empty() {
                self.writeln(format_args!("{}", lines.join("\n")))?;
            }
            Ok(())
        }

        fn write_other_parents(&mut self, peer_id: &S::PublicId) -> io::Result<()> {
            let mut lines = vec![];
            for event in self
                .peer_list
                .peer_events(peer_id)
                .filter_map(|hash| self.gossip_graph.get(hash))
            {
                if let Some(other_parent) = event
                    .other_parent()
                    .and_then(|other_hash| self.gossip_graph.get(other_hash))
                {
                    lines.push(format!(
                        "  \"{}\" -> \"{}\" [constraint=false]",
                        other_parent.short_name(),
                        event.short_name()
                    ));
                }
            }
            self.writeln(format_args!("{}", lines.join("\n")))?;
            self.writeln(format_args!(""))
        }

        fn write_peers(&mut self) -> io::Result<()> {
            self.writeln(format_args!("  {{"))?;
            self.writeln(format_args!("    rank=same"))?;
            let mut peer_ids = self.peer_list.all_ids().collect::<Vec<_>>();
            for peer_id in &peer_ids {
                self.writeln(format_args!(
                    "    {:?} [style=filled, color=white]",
                    peer_id
                ))?;
            }
            self.writeln(format_args!("  }}"))?;

            let mut peer_order = String::new();
            let last_peer_id = peer_ids.pop();
            for peer_id in peer_ids {
                peer_order.push_str(&format!("{:?} -> ", peer_id));
            }
            if let Some(peer_id) = last_peer_id {
                peer_order.push_str(&format!("{:?} [style=invis]", peer_id));
            }
            self.writeln(format_args!("  {}\n", peer_order))
        }

        fn write_event_details(&mut self, peer_id: &S::PublicId) -> io::Result<()> {
            let current_meta_events = self.meta_elections.current_meta_events();
            for event_hash in self.peer_list.peer_events(peer_id) {
                if let Some(event) = self.gossip_graph.get(event_hash) {
                    let attr = EventAttributes::new(event, current_meta_events.get(event_hash));
                    self.writeln(format_args!(
                        "  \"{}\" {}",
                        event.short_name(),
                        attr.to_string()
                    ))?;
                    event.write_to_dot_format(&mut self.file)?;
                    self.writeln(format_args!(""))?;
                }
            }
            Ok(())
        }

        fn write_meta_elections(&mut self) -> io::Result<()> {
            let indent = self.indentation();
            self.writeln(format_args!(
                "{}{}===== meta-elections =====",
                Self::COMMENT,
                indent
            ))?;
            let mut lines = vec![];
            lines.push(format!(
                "{}{}consensus_history:",
                Self::COMMENT,
                self.indentation()
            ));
            for hash in self.meta_elections.consensus_history() {
                lines.push(format!(
                    "{}{}{}",
                    Self::COMMENT,
                    self.indentation(),
                    hash.as_full_string()
                ));
            }
            for handle in self.meta_elections.all() {
                let election = unwrap!(self.meta_elections.get(handle));
                lines.push("".to_string());
                lines.push(format!(
                    "{}{}{:?}",
                    Self::COMMENT,
                    self.indentation(),
                    handle
                ));
                lines.push(format!(
                    "{}{}consensus_len: {}",
                    Self::COMMENT,
                    self.indentation(),
                    election.consensus_len
                ));

                // write round hashes
                lines.push(format!(
                    "{}{}round_hashes: {{",
                    Self::COMMENT,
                    self.indentation()
                ));
                self.indent();
                for (peer, hashes) in &election.round_hashes {
                    lines.push(format!(
                        "{}{}{:?} -> [",
                        Self::COMMENT,
                        self.indentation(),
                        peer
                    ));
                    self.indent();
                    for hash in hashes {
                        lines.push(format!(
                            "{}{}RoundHash {{ round: {}, latest_block_hash: {} }}",
                            Self::COMMENT,
                            self.indentation(),
                            hash.round(),
                            hash.latest_block_hash().as_full_string(),
                        ));
                    }
                    self.dedent();
                    lines.push(format!("{}{}]", Self::COMMENT, self.indentation()));
                }
                self.dedent();
                lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));

                // write interesting events
                lines.push(format!(
                    "{}{}interesting_events: {{",
                    Self::COMMENT,
                    self.indentation()
                ));
                self.indent();
                for (peer, events) in &election.interesting_events {
                    let event_names: Vec<String> = events
                        .iter()
                        .filter_map(|hash| self.hash_to_short_name(hash))
                        .collect();
                    lines.push(format!(
                        "{}{}{:?} -> {:?}",
                        Self::COMMENT,
                        self.indentation(),
                        peer,
                        event_names
                    ));
                }
                self.dedent();
                lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));

                // write all voters
                lines.push(format!(
                    "{}{}all_voters: {:?}",
                    Self::COMMENT,
                    self.indentation(),
                    &election.all_voters
                ));

                // write undecided voters
                lines.push(format!(
                    "{}{}undecided_voters: {:?}",
                    Self::COMMENT,
                    self.indentation(),
                    &election.undecided_voters
                ));

                // write payload
                if let Some(ref payload) = election.payload {
                    lines.push(format!(
                        "{}{}payload: {:?}",
                        Self::COMMENT,
                        self.indentation(),
                        payload
                    ));
                }

                // write meta-events
                lines.push(format!(
                    "{}{}meta_events: {{",
                    Self::COMMENT,
                    self.indentation()
                ));
                self.indent();
                // sort by creator, then index
                let meta_events = election
                    .meta_events
                    .iter()
                    .map(|(hash, mev)| {
                        let event = unwrap!(self.gossip_graph.get(hash));
                        let creator_and_index = (event.creator(), event.index());
                        let short_name_and_mev = (event.short_name(), mev);
                        (creator_and_index, short_name_and_mev)
                    }).collect::<BTreeMap<_, _>>();

                for (short_name, mev) in meta_events.values() {
                    lines.push(format!(
                        "{}{}{} -> {{",
                        Self::COMMENT,
                        self.indentation(),
                        short_name
                    ));
                    self.indent();
                    lines.push(format!(
                        "{}{}observees: {:?}",
                        Self::COMMENT,
                        self.indentation(),
                        mev.observees
                    ));
                    lines.push(format!(
                        "{}{}interesting_content: {:?}",
                        Self::COMMENT,
                        self.indentation(),
                        mev.interesting_content
                    ));

                    if !mev.meta_votes.is_empty() {
                        lines.push(format!(
                            "{}{}meta_votes: {{",
                            Self::COMMENT,
                            self.indentation()
                        ));
                        self.indent();
                        lines.extend(
                            dump_meta_votes(&mev.meta_votes, true)
                                .into_iter()
                                .map(|s| format!("{}{}{}", Self::COMMENT, self.indentation(), s)),
                        );
                        self.dedent();
                        lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));
                    }
                    self.dedent();

                    lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));
                }
                self.dedent();
                lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));
            }
            self.writeln(format_args!("{}", lines.join("\n")))?;
            Ok(())
        }
    }

    struct EventAttributes {
        label: String,
        fillcolor: &'static str,
        is_rectangle: bool,
    }

    impl EventAttributes {
        fn new<T: NetworkEvent, P: PublicId>(
            event: &Event<T, P>,
            opt_meta_event: Option<&MetaEvent<T, P>>,
        ) -> Self {
            let mut attr = EventAttributes {
                fillcolor: "fillcolor=white",
                is_rectangle: false,
                label: event.short_name(),
            };

            attr.label = format!(
                "<table border=\"0\" cellborder=\"0\" \
                 cellpadding=\"0\" cellspacing=\"0\">\n\
                 <tr><td colspan=\"6\">{}</td></tr>\n",
                attr.label
            );

            if let Some(event_payload) = event.vote().map(Vote::payload) {
                attr.label = format!(
                    "{}<tr><td colspan=\"6\">{:?}</td></tr>\n",
                    attr.label, event_payload
                );
                attr.fillcolor = "style=filled, fillcolor=cyan";
                attr.is_rectangle = true;
            }

            if let Some(meta_event) = opt_meta_event {
                if !meta_event.interesting_content.is_empty() {
                    attr.label = format!(
                        "{}<tr><td colspan=\"6\">{:?}</td></tr>",
                        attr.label, meta_event.interesting_content
                    );
                    attr.fillcolor = "style=filled, fillcolor=crimson";
                    attr.is_rectangle = true;
                }
                if !meta_event.meta_votes.is_empty() {
                    let meta_votes = dump_meta_votes(&meta_event.meta_votes, false).join("\n");
                    attr.label = format!("{}{}", attr.label, meta_votes);
                }
                attr.is_rectangle = true;
            }

            attr.label = format!("{}</table>", attr.label);
            attr
        }

        fn to_string(&self) -> String {
            format!(
                "[{}, {}label=<{}>]",
                self.fillcolor,
                if self.is_rectangle {
                    "shape=rectangle, "
                } else {
                    ""
                },
                self.label
            )
        }
    }
}
