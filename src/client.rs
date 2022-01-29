use crate::error::Error;
use crate::http::DualSchemeClient;
use crate::peer::proto::Message;
use crate::peer::{PeerInfo, PeerConn, PortRange};
use crate::torrent::metainfo::{Files, Metainfo};
use crate::torrent::{Torrent, TorrentAnnounceState};
use crate::tracker::{TrackerClient, TrackerClientOptions};
use crate::bitfield::Bitfield;
use crate::resolver;

use chashmap::CHashMap;
use chrono::Utc;
use tokio::task;
use tokio::time::sleep;

use std::default::Default;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::cmp::{max, min};
use std::collections::HashMap;

fn print_metainfo_files(metainfo: &Metainfo) {
    println!("[debug] torrent files:");
    match &metainfo.info.files {
        Files::Multiple(dir) => {
            for file in &dir.files {
                println!("- {}/{}", dir.name, file);
            }
        }
        Files::Single(file) => {
            println!("- {}", file);
        }
    };
    println!(" ");
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ClientOptions {
    pub ip: IpAddr,
    pub port_range: PortRange,
    pub download_dir: PathBuf,
    pub min_interval: Duration,
    pub max_interval: Duration,
    pub default_interval: Duration,
    pub block_size: usize,
    pub tracker: Option<String>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port_range: PortRange::from(1024..=65535),
            download_dir: ".".into(),
            min_interval: Duration::from_secs(5),
            max_interval: Duration::from_secs(900),
            default_interval: Duration::from_secs(60),
            block_size: 16384,
            tracker: None,
        }
    }
}

pub struct Client {
    pub opts: ClientOptions,
    local_peer: PeerInfo,
    pub torrents: CHashMap<[u8; 20], Torrent>,
}

impl Client {
    pub fn new(opts: ClientOptions) -> Self {
        let local_peer = PeerInfo::new_local("-RS0001-", opts.ip, opts.port_range);
        if crate::DEBUG {
            println!("[debug] local peer: {}", local_peer);
        }
        Self {
            opts,
            local_peer,
            torrents: CHashMap::new(),
        }
    }

    /// Download method, implementing rarest first piece selection algorithm:
    /// https://wiki.theory.org/Availability
    ///
    /// Only leeches for now, need to implement a per-Client Torrent store,
    /// then add the torrent to the store/queue for leeching+seeding.
    ///
    /// Steps to download rarest pieces first:
    /// - 1. connect to a bunch of peers and read their bitfields
    /// - 2. find the rarest piece(s)
    /// - 3. pick a random piece from the rarest piece(s)
    /// - 4. create a work queue for each peer
    /// - 5. start requesting piece blocks from all peers
    pub async fn download(self: Arc<Self>, torrent: &str) -> Result<(), Error> {
        // create tracker client
        let resolver = resolver::cloudflare_https(resolver::default_opts())?;
        let tracker_client = TrackerClient::new_with_resolver(
            resolver.clone(),
            TrackerClientOptions::default(),
            &self.local_peer,
        );

        // read torrent from file or URI
        let http_client = DualSchemeClient::new_with_resolver(resolver.into());
        let mut torrent = Torrent::from_file_or_url(
            torrent,
            &http_client,
            &self.local_peer,
            self.opts.block_size,
        )
        .await?;

        // replace announce list if tracker specified
        if let Some(tracker) = &self.opts.tracker {
            torrent.announce = vec![vec![tracker.clone()].into()];
        }

        // add torrent to client
        let info_hash = torrent.metainfo.info_hash;
        if self.torrents.contains_key(&info_hash) {
            // TODO: un-pause torrent if paused
            return Ok(());
        }
        self.torrents.insert(info_hash, torrent);

        // get new reference to torrent
        let torrent = self.torrents.get(&info_hash).unwrap();

        // print files when starting download
        if crate::DEBUG {
            print_metainfo_files(&torrent.metainfo);
        }

        // TODO: handle incoming connections

        // announce / peer select loop, which repeatedly announces and
        // attempts to establish more peer connections, if more peers are available
        // and we have less peers than desired
        let mut announce_states: HashMap<[u8; 20], TorrentAnnounceState> = HashMap::new();
        announce_states.insert(torrent.metainfo.info_hash, TorrentAnnounceState::default());
        loop {
            let state = match announce_states.get_mut(&torrent.metainfo.info_hash) {
                Some(state) => state,
                None => return Err(Error::InfoHashInvalid),
            };

            // decide whether to announce or not, based on time since last time
            let should_announce = {
                if let Some(last_time) = state.last_time {
                    let min_interval = if let Some(last_announce) = &state.last_announce {
                        max(
                            last_announce.min_interval.unwrap_or(self.opts.min_interval),
                            self.opts.min_interval,
                        )
                    } else {
                        self.opts.min_interval
                    };
                    let interval = if let Some(last_announce) = &state.last_announce {
                        last_announce.interval
                    } else {
                        self.opts.default_interval
                    };
                    let interval = min(self.opts.max_interval, max(interval, min_interval));
                    let now = Utc::now();
                    let time_since_last_announce = (now - last_time).to_std().unwrap();
                    if crate::DEBUG {
                        println!(
                            "[debug] time until next announce: {:?}",
                            interval - time_since_last_announce
                        );
                    }
                    time_since_last_announce >= interval
                } else {
                    // haven't announced yet, announce now
                    true
                }
            };

            // perform announce, if needed
            // TODO: announce faster if we need new peers, due to snubbing or disconnections?
            // TODO: set larger num_want, so we can keep a cache of not-yet-attempted peers?
            if should_announce {
                if crate::DEBUG {
                    println!("[debug] announcing...");
                }
                let tracker_id = if let Some(last_announce) = &state.last_announce {
                    last_announce.tracker_id.as_deref()
                } else {
                    None
                };
                match tracker_client.announce(&torrent, tracker_id).await {
                    Ok(announce) => {
                        let mut new_peers: Vec<PeerInfo> = Vec::new();
                        for peer_info in announce.peers.clone() {
                            torrent.peer_bitfields.upsert(
                                peer_info,
                                || {
                                    new_peers.push(peer_info);
                                    Bitfield::new(torrent.metainfo.info.piece_hashes.len())
                                },
                                |_| (),
                            );
                        }

                        state.last_announce = Some(announce);
                        state.last_time = Some(Utc::now());

                        // connect to and handshake with new peers
                        println!("[debug] new peers:");
                        for peer_info in new_peers {
                            println!("- {}", &peer_info);
                            task::spawn(
                                self.clone().connect_and_run_event_loop(
                                    peer_info,
                                    torrent.metainfo.info_hash,
                                ),
                            );
                        }
                        println!(" ");
                    }
                    Err(e) => {
                        if crate::DEBUG {
                            println!("[debug] announce failed: {}", e);
                        }
                    }
                }
            }

            sleep(Duration::from_secs(10)).await;
        }
    }

    pub async fn connect_and_run_event_loop(
        self: Arc<Self>,
        peer_info: PeerInfo,
        info_hash: [u8; 20],
    ) {
        let torrent = match self.torrents.get(&info_hash) {
            Some(torrent) => torrent,
            None => {
                if crate::DEBUG {
                    println!("[debug] torrent not found in client");
                }
                return;
            }
        };
        let peer_bitfield = match torrent.peer_bitfields.get(&peer_info) {
            Some(peer_bitfield) => peer_bitfield,
            None => {
                if crate::DEBUG {
                    println!("[debug] torrent not found in client");
                }
                return;
            },
        };

        match PeerConn::connect(peer_info, info_hash).await {
            Ok(mut conn) => {
                // handshake with peer
                match conn.handshake(self.clone()).await {
                    Ok(_) => {
                        if crate::DEBUG {
                            println!("[debug] connected to peer {}", &peer_info);
                        }
                        // torrent.active_peers.fetch_add(1, Ordering::SeqCst);

                        // if we have some pieces, send bitfield
                        let bitfield = torrent.pieces.as_bitfield();
                        if !bitfield.is_all_clear() {
                            if crate::DEBUG {
                                println!(
                                    "[debug] sending bitfield to peer {}: {:?}",
                                    &peer_info, &bitfield
                                );
                            }
                            match conn.write(Message::Bitfield(bitfield)).await {
                                Ok(_) => {
                                    match conn.run_event_loop(self.clone()).await {
                                        Ok(_) => {
                                            if crate::DEBUG {
                                                println!(
                                                    "[debug] disconnected from peer {}",
                                                    &peer_info
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            if crate::DEBUG {
                                                println!(
                                                    "[debug] disconnected from peer {}: {:?}",
                                                    &peer_info, e
                                                );
                                            }
                                        }
                                    };
                                }
                                Err(e) => {
                                    println!(
                                        "[warning] unable to send our bitfield to peer {}: {}",
                                        &peer_info, e
                                    );
                                }
                            }
                        }

                        // torrent.active_peers.fetch_sub(1, Ordering::SeqCst);
                        let _ = torrent.pieces.decrease_availability(&peer_bitfield).await;
                    }
                    Err(e) => {
                        println!(
                            "[warning] unable to handshake with peer {}: {}",
                            &peer_info, e
                        );
                    }
                }
            }
            Err(e) => {
                if crate::DEBUG {
                    println!("[debug] error connecting to peer {}: {}", &peer_info, e);
                }
            }
        }

        // remove peer bitfield when disconnected
        torrent.peer_bitfields.remove(&peer_info);
    }
}
