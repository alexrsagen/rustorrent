pub mod metainfo;
use metainfo::Metainfo;

pub mod piece;
use piece::PieceStore;

use crate::error::Error;
use crate::http::{read_body, DualSchemeClient};
use crate::peer::{Peer, PeerInfo, Peers};
use crate::peer::proto::Handshake;
use crate::tracker::announce::Announce;
use crate::skip_wrap_vec::SkipWrapVec;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use rand::seq::SliceRandom;
use tokio::fs;
use tokio::sync::RwLock;

use std::convert::TryInto;
use std::default::Default;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TorrentStatus {
    Queued,
    Checking,
    Leeching,
    Seeding,
    Finished,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TorrentAnnounceState {
    pub last_time: Option<DateTime<Utc>>,
    pub last_announce: Option<Announce>,
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
    pub announce: Vec<SkipWrapVec<String>>,
    pub announce_state: RwLock<TorrentAnnounceState>,
    pub handshake: Handshake,
}

impl Torrent {
    pub fn new(metainfo: Metainfo, local_peer: &PeerInfo, block_size: usize) -> Self {
        // prepare announce list
        let mut announce = metainfo.announce.clone();
        announce.shuffle(&mut rand::thread_rng());
        let announce = announce.into_iter().map(SkipWrapVec::from).collect();

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

    pub async fn from_file_or_url(
        path: &str,
        client: &DualSchemeClient,
        local_peer: &PeerInfo,
        block_size: usize,
    ) -> Result<Self, Error> {
        if &path[..7] == "http://" || &path[..8] == "https://" {
            Self::from_url(path, client, local_peer, block_size).await
        } else {
            Self::from_file(path, local_peer, block_size).await
        }
    }

    pub async fn from_file(
        path: &str,
        local_peer: &PeerInfo,
        block_size: usize,
    ) -> Result<Self, Error> {
        let bytes = fs::read(path).await?;
        let metainfo = bytes.try_into()?;
        Ok(Self::new(metainfo, local_peer, block_size))
    }

    pub async fn from_url(
        path: &str,
        client: &DualSchemeClient,
        local_peer: &PeerInfo,
        block_size: usize,
    ) -> Result<Self, Error> {
        let metainfo_uri = path.parse::<hyper::Uri>()?;
        if crate::DEBUG {
            println!("[debug] HTTP GET {}", &path);
        }
        let mut res = client.get(&metainfo_uri).await?;
        if crate::DEBUG {
            println!("[debug] {:?} {}", res.version(), res.status());
        }
        let bytes = read_body(&mut res).await?;
        let metainfo = bytes.try_into()?;
        Ok(Self::new(metainfo, local_peer, block_size))
    }

    pub async fn has_peer(&self, info: &PeerInfo) -> bool {
        self.peers
            .read()
            .await
            .iter()
            .any(|peer| &peer.info == info)
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
            .collect()
            .await;

        self.peers.write().await.append(&mut new_peers);
    }
}
