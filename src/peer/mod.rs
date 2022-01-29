use crate::torrent::metainfo::InfoHash;

pub mod conn;
pub use conn::{PeerConn, PeerConnState};

pub mod addr_and_id;
pub use addr_and_id::PeerAddrAndId;

mod port_range;
pub use port_range::PortRange;

pub mod proto;

pub type PeerId = [u8; 20];

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct TorrentPeerKey {
    pub peer_id: PeerId,
    pub info_hash: InfoHash,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct TorrentPeerInfo {
    pub addr_and_id: PeerAddrAndId,
    pub info_hash: InfoHash,
}
