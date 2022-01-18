use tokio::task;
use tokio::time::sleep;

use crate::resolver;

use crate::http::DualSchemeClient;
use rand::seq::SliceRandom;
use chrono::Utc;

use crate::torrent::Torrent;
use crate::torrent::metainfo::{Metainfo, Files};

use crate::tracker::{TrackerClient, TrackerClientOptions};

use crate::peer::{PortRange, Peers, Peer, PeerInfo};

use crate::error::Error;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc};
use std::default::Default;
use std::time::Duration;
use std::cmp::{min, max};

fn print_metainfo_files(metainfo: &Metainfo) {
	println!("[debug] torrent files:");
	match &metainfo.info.files {
		Files::Multiple(dir) => {
			for file in &dir.files {
				println!("- {}/{}", dir.name, file);
			}
		},
		Files::Single(file) => {
			println!("- {}", file);
		},
	};
	println!("");
}

async fn print_peers(peers: &Peers) {
	println!("[debug] torrent peers:");
	for peer in peers.read().await.iter() {
		println!("- {}", &peer.info);
	}
	println!("");
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
		}
	}
}

#[derive(Debug, Clone)]
pub struct Client {
	pub opts: ClientOptions,
	local_peer: Arc<PeerInfo>,
}

impl Client {
	pub fn new(opts: ClientOptions) -> Self {
		let local_peer = Arc::new(PeerInfo::new_local("-RS0001-", opts.ip, opts.port_range));
		if crate::DEBUG {
			println!("[debug] local peer: {}", local_peer);
		}
		Self { opts, local_peer }
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
	pub async fn download(&self, torrent: &str) -> Result<(), Error> {
		// create tracker client
		let resolver = resolver::cloudflare_https(resolver::default_opts())?;
		let tracker_client = TrackerClient::new_with_resolver(resolver.clone(), TrackerClientOptions::default(), &self.local_peer);

		// read torrent from file or URI
		let http_client = DualSchemeClient::new_with_resolver(resolver.into());
		let torrent = Arc::new(Torrent::from_file_or_url(torrent, &http_client, &self.local_peer, self.opts.block_size).await?);
		print_metainfo_files(&torrent.metainfo);

		// TODO: handle incoming connections

		// announce / peer select loop, which repeatedly announces and
		// attempts to establish more peer connections, if more peers are available
		// and we have less peers than desired
		loop {
			let state = torrent.announce_state.read().await;
			let min_interval = if let Some(last_announce) = &state.last_announce {
				max(
					last_announce.min_interval.unwrap_or(self.opts.min_interval),
					self.opts.min_interval
				)
			} else {
				self.opts.min_interval
			};
			let interval = if let Some(last_announce) = &state.last_announce {
				last_announce.interval
			} else {
				self.opts.default_interval
			};
			let interval = min(
				self.opts.max_interval,
				max(
					interval,
					min_interval
				)
			);
			let now = Utc::now();
			let now_minus_interval = now.checked_sub_signed(chrono::Duration::from_std(interval).unwrap()).unwrap();
			let last_announce = state.last_time.unwrap_or(now_minus_interval);
			let time_since_last_announce = (now - last_announce).to_std().unwrap();
			std::mem::drop(state);

			if crate::DEBUG {
				println!("[debug] time until next announce: {:?}", interval - time_since_last_announce);
			}

			// perform announce, if needed
			// TODO: announce faster if we need new peers, due to snubbing or disconnections?
			// TODO: set larger num_want, so we can keep a cache of not-yet-attempted peers?
			if time_since_last_announce >= interval {
				if crate::DEBUG {
					println!("[debug] announcing...");
				}
				let mut state = torrent.announce_state.write().await;
				let tracker_id = if let Some(last_announce) = &state.last_announce {
					last_announce.tracker_id.as_deref()
				} else {
					None
				};
				match tracker_client.announce(&torrent, tracker_id).await {
					Ok(announce) => {
						let mut peers: Vec<Peer> = announce.peers.iter()
							.map(|peer| Peer::new(peer.clone(), torrent.clone()))
							.collect();

						peers.shuffle(&mut rand::thread_rng());
						torrent.append_peers(peers).await;
						if crate::DEBUG {
							print_peers(&torrent.peers).await;
						}

						state.last_announce = Some(announce);
						state.last_time = Some(Utc::now());
					},
					Err(e) => {
						if crate::DEBUG {
							println!("[debug] announce failed: {}", e);
						}
					}
				}
			}

			// connect to and handshake with new peers
			for peer in torrent.peers.read().await.iter() {
				task::spawn(peer.clone().connect_and_run_event_loop());
			}

			sleep(Duration::from_secs(10)).await;
		}
	}
}