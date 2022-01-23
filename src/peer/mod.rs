pub mod conn;
pub use conn::{PeerConn, PeerConnState};

pub mod info;
pub use info::PeerInfo;

pub mod proto;
use proto::Message;

mod port_range;
pub use port_range::PortRange;

use crate::bitfield::Bitfield;
use crate::client::Client;
use crate::error::Error;

use tokio::sync::Mutex;

use std::time::Duration;
use std::sync::Arc;

#[derive(Debug)]
pub enum PeerError {
    ConnectionError(Error),
    ReadError(Error),
    WriteError(Error),
}

#[derive(Debug)]
pub struct Peer {
    pub info: PeerInfo,
    pub info_hash: [u8; 20],
    pub bitfield: Bitfield,
    conn: Mutex<Option<PeerConn>>, // TODO: eliminate mutex
}

impl Peer {
    pub fn new(info: PeerInfo, info_hash: [u8; 20], client: Arc<Client>) -> Self {
        let torrent = client.torrents.get(&info_hash);
        let bitfield = match torrent {
            Some(torrent) => Bitfield::new(torrent.metainfo.info.piece_hashes.len()),
            None => Bitfield::new(0)
        };
        Self {
            info,
            info_hash,
            bitfield,
            conn: Mutex::new(None),
        }
    }

    pub async fn connect(&self) -> Result<(), Error> {
        let mut guard = self.conn.lock().await;
        if guard.is_some() {
            if crate::DEBUG {
                println!("[debug] already connected to peer {}...", &self.info);
            }
            return Ok(());
        }
        // connect to peer
        if crate::DEBUG {
            println!("[debug] connecting to peer {}...", &self.info);
        }
        match PeerConn::connect(self.info.addr).await {
            Ok(conn) => {
                *guard = Some(conn);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub async fn handshake(&self, client: Arc<Client>) -> Result<(), Error> {
        let torrent = match client.torrents.get(&self.info_hash) {
            Some(torrent) => torrent,
            None => return Err(Error::InfoHashInvalid),
        };
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            return Err(Error::NotConnected);
        }
        let conn = guard.as_mut().unwrap();
        conn.write_handshake(&torrent.handshake).await?;
        conn.flush().await?;
        let handshake = conn.read_handshake().await?;
        // check peer_id against known value, if known
        if let Some(peer_id) = self.info.id {
            if handshake.peer_id != peer_id {
                return Err(Error::PeerIdInvalid);
            }
        }
        // check info_hash against known value
        if handshake.info_hash != torrent.metainfo.info_hash {
            return Err(Error::InfoHashInvalid);
        }
        Ok(())
    }

    // only returns Ok(m) where m:
    // - Message::Request(_)
    // - Message::Piece(_)
    // - Message::Cancel(_)
    // - Message::Port(_)
    // otherwise, returns Error::MessageHandled
    pub async fn read(&self, client: Arc<Client>) -> Result<Message, Error> {
        let torrent = match client.torrents.get(&self.info_hash) {
            Some(torrent) => torrent,
            None => return Err(Error::InfoHashInvalid),
        };
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            return Err(Error::NotConnected);
        }
        let conn = guard.as_mut().unwrap();
        let msg = conn.read_msg().await?;
        conn.state.rx_msg_count += 1;
        match msg {
            Message::InvalidId => Err(Error::MessageIdInvalid),
            Message::InvalidLength => Err(Error::MessageLengthInvalid),
            Message::Keepalive => Err(Error::MessageHandled),
            Message::Choke => {
                if crate::DEBUG {
                    println!("[debug] peer {} is choking", &self.info);
                }
                conn.state.peer_choking = true;
                Err(Error::MessageHandled)
            }
            Message::Unchoke => {
                if crate::DEBUG {
                    println!("[debug] peer {} no longer choking", &self.info);
                }
                conn.state.peer_choking = false;
                Err(Error::MessageHandled)
            }
            Message::Interested => {
                if crate::DEBUG {
                    println!("[debug] peer {} is interested", &self.info);
                }
                conn.state.peer_interested = true;
                Err(Error::MessageHandled)
            }
            Message::NotInterested => {
                if crate::DEBUG {
                    println!("[debug] peer {} is no longer interested", &self.info);
                }
                conn.state.peer_interested = false;
                Err(Error::MessageHandled)
            }
            Message::Have(index) => {
                if crate::DEBUG {
                    println!("[debug] peer {} has piece {}", &self.info, index);
                }
                self.bitfield.set_bit(index as usize);
                torrent.pieces.increase_availability(&self.bitfield).await?;
                Err(Error::MessageHandled)
            }
            Message::Bitfield(mut bitfield) => {
                if conn.state.rx_msg_count != 1 {
                    return Err(Error::UnexpectedOrInvalidBitfield);
                }
                bitfield.resize(torrent.metainfo.info.piece_hashes.len());
                if bitfield.spare_bits_as_byte() != 0 {
                    return Err(Error::UnexpectedOrInvalidBitfield);
                }
                if crate::DEBUG {
                    println!("[debug] peer {} sent {:?}", &self.info, &bitfield);
                }
                torrent.pieces.increase_availability(&bitfield).await?;
                self.bitfield.try_overwrite_with(&bitfield)?;
                Err(Error::MessageHandled)
            }
            Message::Piece(block) => {
                torrent.pieces.write_block(&self, client.clone(), block).await?;
                Err(Error::MessageHandled)
            }
            Message::Request(request) => {
                if crate::DEBUG {
                    println!(
                        "[debug] peer {} requested block of piece {} (offset {}, length {})",
                        &self.info, request.index, request.begin, request.length
                    );
                }
                if conn.state.am_choking {
                    // TODO: ignore piece request
                } else {
                    // TODO: handle piece request
                }
                Err(Error::MessageHandled)
            }
            Message::Cancel(request) => {
                if crate::DEBUG {
                    println!("[debug] peer {} cancelled request for block of piece {} (offset {}, length {})", &self.info, request.index, request.begin, request.length);
                }
                if conn.state.am_choking {
                    // TODO: ignore piece cancel request
                } else {
                    // TODO: handle piece cancel request
                }
                Err(Error::MessageHandled)
            }
            msg => Ok(msg),
        }
    }

    pub async fn write(&self, msg: Message) -> Result<(), Error> {
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            return Err(Error::NotConnected);
        }
        let conn = guard.as_mut().unwrap();
        let mut am_choking = conn.state.am_choking;
        let mut am_interested = conn.state.am_interested;
        match &msg {
            Message::Choke => {
                if am_choking {
                    return Err(Error::NoOp);
                }
                am_choking = true;
            }
            Message::Unchoke => {
                if !am_choking {
                    return Err(Error::NoOp);
                }
                am_choking = false;
            }
            Message::Interested => {
                if am_interested {
                    return Err(Error::NoOp);
                }
                am_interested = true;
            }
            Message::NotInterested => {
                if !am_interested {
                    return Err(Error::NoOp);
                }
                am_interested = false;
            }
            Message::Request(_) => {
                if conn.state.peer_choking {
                    return Err(Error::PeerChoking);
                }
            }
            Message::Cancel(_) => {
                if conn.state.peer_choking {
                    return Err(Error::PeerChoking);
                }
            }
            _ => {}
        }
        conn.write_msg(msg).await?;
        conn.state.tx_msg_count += 1;
        conn.state.am_choking = am_choking;
        conn.state.am_interested = am_interested;
        Ok(())
    }

    pub async fn keepalive(&self) -> Result<(), Error> {
        let keepalive_interval_passed = {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                return Err(Error::NotConnected);
            }
            let conn = guard.as_mut().unwrap();
            let keepalive_interval =
                conn.opts.keepalive_interval - conn.opts.tx_timeout.unwrap_or(Duration::from_secs(5));
            conn.duration_since_last_tx() > keepalive_interval
        };
        if keepalive_interval_passed {
            self.write(Message::Keepalive).await
        } else {
            Ok(())
        }
    }

    pub async fn flush(&self) -> Result<(), Error> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_mut() {
            return conn.flush().await;
        }
        Err(Error::NotConnected)
    }

    pub async fn state(&self) -> Result<PeerConnState, Error> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_mut() {
            return Ok(conn.state);
        }
        Err(Error::NotConnected)
    }

    pub async fn run_event_loop(&self, client: Arc<Client>) -> Result<(), PeerError> {
        let torrent = match client.torrents.get(&self.info_hash) {
            Some(torrent) => torrent,
            None => return Err(PeerError::ConnectionError(Error::InfoHashInvalid)),
        };
        // run event loop
        loop {
            if crate::DEBUG {
                println!("[debug] polling for peer {} message...", &self.info);
            }
            match self.read(client.clone()).await {
                Ok(msg) => {
                    match msg {
                        Message::Port(dht_port) => {
                            if crate::DEBUG {
                                println!(
                                    "[debug] peer {} sent DHT port: {:?}",
                                    &self.info, dht_port
                                );
                            }
                            // TODO: DHT related, insert peer into "local routing table"
                        }
                        msg => {
                            if crate::DEBUG {
                                println!(
                                    "[debug] peer {} sent unhandled message: {:?}",
                                    &self.info, msg
                                );
                            }
                        }
                    }
                }
                Err(Error::Timeout(_)) => {}
                Err(Error::MessageHandled) => {}
                Err(Error::UnsolicitedPieceBlockMessage {
                    piece_index,
                    block_index,
                }) => {
                    println!(
                        "[warning] peer {} sent unsolicited block {} of piece {}",
                        &self.info, block_index, piece_index
                    );
                }
                Err(Error::InvalidPieceBlockMessage {
                    piece_index,
                    block_index,
                }) => {
                    println!("[warning] peer {} sent invalid block {} of piece {} (wrong begin or length)", &self.info, block_index, piece_index);
                }
                Err(Error::PieceHashInvalid { piece_index }) => {
                    println!(
                        "[warning] piece {} could not be verified and will be re-downloaded",
                        piece_index
                    );
                }
                Err(e) => return Err(PeerError::ReadError(e)),
            }

            // update interested state by comparing peer bitfield with torrent bitfield
            let bitfield = torrent.pieces.as_bitfield();
            let bitfield_interesting = self.bitfield.except(&bitfield);
            let msg_interest = if bitfield_interesting.is_all_clear() {
                Message::NotInterested
            } else {
                Message::Interested
            };
            // send message (NoOp = already same state)
            if crate::DEBUG {
                println!(
                    "[debug] updating peer {} interest: {:?}",
                    &self.info, &msg_interest
                );
            }
            match self.write(msg_interest).await {
                Ok(_) => {
                }
                Err(Error::NoOp) => {}
                Err(e) => return Err(PeerError::WriteError(e)),
            }

            // TODO: choke/unchoke peer here, but make the decision elsewhere(?)
            // need to implement a choking/unchoking algorithm

            // TODO: implement disconnect: return Ok(state)

            if !self
                .state()
                .await
                .map_err(|e| PeerError::ConnectionError(e))?
                .peer_choking
            {
                // TODO: request pieces from peer
                // TODO: - pipelining and adaptive queueing (https://luminarys.com/posts/writing-a-bittorrent-client.html)
                // match self.write(Message::Request(req.clone())).await {
                // 	Ok(_) => {
                // 		// self.requests.push(req);
                // 	},
                // 	Err(e) => {
                // 		self.peer.torrent.req_queue.push(req);
                // 		return Err(PeerError::WriteError(e))
                // 	},
                // }
            }

            // keep connection alive
            self.keepalive()
                .await
                .map_err(|e| PeerError::WriteError(e))?;

            // flush all messages to peer
            self.flush().await.map_err(|e| PeerError::WriteError(e))?;

            // TODO: find and cancel timed out requests
        }
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info
    }
}
