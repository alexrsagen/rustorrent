pub mod metainfo;
use metainfo::Metainfo;

pub mod piece;
use piece::PieceStore;

use crate::error::Error;
use crate::http::{read_body, DualSchemeClient};
use crate::peer::{Peer, PeerInfo, Peers, proto::Handshake};
use crate::tracker::announce::Announce;

use tokio::fs;
use rand::seq::SliceRandom;
use futures::StreamExt;
use tokio::sync::{Mutex, RwLock};
use chrono::{DateTime, Utc};

use std::convert::TryInto;
use std::sync::{Arc, atomic::AtomicUsize};
use std::default::Default;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TorrentStatus {
	Queued,
	Checking,
	Leeching,
	Seeding,
	Finished,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TorrentAnnounceState {
	pub last_time: Option<DateTime<Utc>>,
	pub last_announce: Option<Announce>,
}

impl Default for TorrentAnnounceState {
	fn default() -> Self {
		Self {
			last_time: None,
			last_announce: None,
		}
	}
}

#[derive(Debug)]
pub struct Torrent {
	pub uploaded: AtomicUsize,
	pub downloaded: AtomicUsize,
	pub status: TorrentStatus,
	pub paused: bool,
	pub peers: Peers,
	// pub active_peers: AtomicUsize,
	pub pieces: PieceStore,
	pub metainfo: Metainfo,
	pub announce: Arc<Vec<Mutex<Vec<String>>>>,
	pub announce_state: RwLock<TorrentAnnounceState>,
	pub handshake: Handshake,
}

impl Torrent {
	pub fn new(metainfo: Metainfo, local_peer: &PeerInfo, block_size: usize) -> Self {
		// prepare announce list
		let mut announce = metainfo.announce.clone();
		announce.shuffle(&mut rand::thread_rng());
		let announce = Arc::new(announce.into_iter().map(|tier| Mutex::new(tier)).collect());

		// prepare handshake
		let handshake = Handshake::new(&metainfo.info_hash, local_peer.id.as_ref().unwrap());

		let piece_count = metainfo.info.piece_hashes.len();
		let piece_size = metainfo.info.piece_length;

		Self {
			uploaded: AtomicUsize::new(0),
			downloaded: AtomicUsize::new(0),
			status: TorrentStatus::Queued,
			paused: false,
			peers: RwLock::new(vec![]),
			// active_peers: AtomicUsize::new(0),
			pieces: PieceStore::new(piece_count, piece_size, block_size),
			metainfo,
			announce,
			announce_state: Default::default(),
			handshake,
		}
	}

	pub fn is_active(&self) -> bool {
		match self.status {
			TorrentStatus::Leeching => !self.paused,
			TorrentStatus::Seeding => !self.paused,
			_ => false,
		}
	}

	pub async fn from_file_or_url(path: &str, client: &DualSchemeClient, local_peer: &PeerInfo, block_size: usize) -> Result<Self, Error> {
		if &path[..7] == "http://" || &path[..8] == "https://" {
			Self::from_url(path, client, local_peer, block_size).await
		} else {
			Self::from_file(path, local_peer, block_size).await
		}
	}

	pub async fn from_file(path: &str, local_peer: &PeerInfo, block_size: usize) -> Result<Self, Error> {
		let bytes = fs::read(path).await?;
		let metainfo = bytes.try_into()?;
		Ok(Self::new(metainfo, local_peer, block_size))
	}

	pub async fn from_url(path: &str, client: &DualSchemeClient, local_peer: &PeerInfo, block_size: usize) -> Result<Self, Error> {
		let metainfo_uri = path.parse::<hyper::Uri>()?;
		let mut res = client.get(&metainfo_uri).await?;
		if crate::DEBUG {
			println!("[debug] HTTP GET {}: {}", &path, res.status());
		}
		let bytes = read_body(&mut res).await?;
		let metainfo = bytes.try_into()?;
		Ok(Self::new(metainfo, local_peer, block_size))
	}

	pub async fn has_peer(&self, info: &PeerInfo) -> bool {
		self.peers.read().await.iter()
			.find(|peer| &peer.info == info)
			.is_some()
	}

	pub async fn append_peers(&self, peers: Vec<Peer>) {
		let mut new_peers = futures::stream::iter(peers.into_iter())
			.filter_map(|peer| async {
				if !self.has_peer(&peer.info).await {
					Some(Arc::new(peer))
				} else {
					None
				}
			})
			.collect().await;

		self.peers.write().await.append(&mut new_peers);
	}
}