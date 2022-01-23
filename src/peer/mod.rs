pub mod conn;
pub use conn::{PeerConn, PeerConnState};

pub mod info;
pub use info::PeerInfo;

pub mod proto;
use proto::Message;

mod port_range;
pub use port_range::PortRange;

use crate::bitfield::Bitfield;
use crate::error::Error;
use crate::torrent::Torrent;

use crossbeam_queue::SegQueue;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;

use std::sync::Arc;
use std::time::Duration;

pub type Peers = RwLock<Vec<Arc<Peer>>>;

#[derive(Debug)]
pub enum PeerError {
    ConnectionError(Error),
    ReadError(Error),
    WriteError(Error),
}

#[derive(Debug)]
pub struct Peer {
    pub info: PeerInfo,
    pub torrent: Arc<Torrent>,
    pub tx_queue: SegQueue<Message>,
    pub bitfield: RwLock<Option<Bitfield>>,
    conn: Mutex<Option<PeerConn>>,
}

impl Peer {
    pub fn new(info: PeerInfo, torrent: Arc<Torrent>) -> Self {
        Self {
            info,
            torrent,
            tx_queue: SegQueue::new(),
            bitfield: RwLock::new(None),
            conn: Mutex::new(None),
        }
    }

    pub async fn connect(&self) -> Result<(), Error> {
        let mut lock = match timeout(Duration::from_secs(10), self.conn.lock()).await {
            Ok(lock) => lock,
            Err(e) => {
                return Err(Error::Timeout(e));
            }
        };

        if lock.is_some() {
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
                *lock = Some(conn);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub async fn handshake(&self) -> Result<(), Error> {
        let mut lock = match timeout(Duration::from_secs(10), self.conn.lock()).await {
            Ok(lock) => lock,
            Err(e) => {
                return Err(Error::Timeout(e));
            }
        };
        let conn = match &mut *lock {
            Some(conn) => conn,
            None => {
                return Err(Error::NotConnected);
            }
        };
        conn.write_handshake(&self.torrent.handshake).await?;
        conn.flush().await?;
        let handshake = conn.read_handshake().await?;
        // check peer_id against known value, if known
        if let Some(peer_id) = self.info.id {
            if handshake.peer_id != peer_id {
                return Err(Error::PeerIdInvalid);
            }
        }
        // check info_hash against known value
        if handshake.info_hash != self.torrent.metainfo.info_hash {
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
    pub async fn read(&self) -> Result<Message, Error> {
        let mut lock = match timeout(Duration::from_secs(10), self.conn.lock()).await {
            Ok(lock) => lock,
            Err(e) => {
                return Err(Error::Timeout(e));
            }
        };
        let conn = match &mut *lock {
            Some(conn) => conn,
            None => {
                return Err(Error::NotConnected);
            }
        };
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
                let mut bitfield_guard = self.bitfield.write().await;
                if bitfield_guard.is_none() {
                    *bitfield_guard =
                        Some(Bitfield::new(self.torrent.metainfo.info.piece_hashes.len()));
                }
                if crate::DEBUG {
                    println!("[debug] peer {} has piece {}", &self.info, index);
                }
                if let Some(bitfield) = bitfield_guard.as_mut() {
                    bitfield.set_bit(index as usize);
                    self.torrent.pieces.increase_availability(&bitfield).await?;
                }
                Err(Error::MessageHandled)
            }
            Message::Bitfield(mut bitfield) => {
                if conn.state.rx_msg_count != 1 {
                    return Err(Error::UnexpectedOrInvalidBitfield);
                }
                let mut bitfield_guard = self.bitfield.write().await;
                if bitfield_guard.is_some() {
                    return Err(Error::UnexpectedOrInvalidBitfield);
                }
                bitfield.resize(self.torrent.metainfo.info.piece_hashes.len());
                if bitfield.spare_bits_as_byte() != 0 {
                    return Err(Error::UnexpectedOrInvalidBitfield);
                }
                if crate::DEBUG {
                    println!("[debug] peer {} sent {:?}", &self.info, &bitfield);
                }
                self.torrent.pieces.increase_availability(&bitfield).await?;
                *bitfield_guard = Some(bitfield);
                Err(Error::MessageHandled)
            }
            Message::Piece(block) => {
                self.torrent.pieces.write_block(&self, block).await?;
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
        let mut lock = match timeout(Duration::from_secs(10), self.conn.lock()).await {
            Ok(lock) => lock,
            Err(e) => {
                return Err(Error::Timeout(e));
            }
        };
        let conn = match &mut *lock {
            Some(conn) => conn,
            None => {
                return Err(Error::NotConnected);
            }
        };
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
        let mut lock = match timeout(Duration::from_secs(10), self.conn.lock()).await {
            Ok(lock) => lock,
            Err(e) => {
                return Err(Error::Timeout(e));
            }
        };
        let conn = match &mut *lock {
            Some(conn) => conn,
            None => {
                return Err(Error::NotConnected);
            }
        };
        let keepalive_interval =
            conn.opts.keepalive_interval - conn.opts.tx_timeout.unwrap_or(Duration::from_secs(5));
        if conn.duration_since_last_tx() > keepalive_interval {
            std::mem::drop(conn);
            std::mem::drop(lock);
            self.write(Message::Keepalive).await?;
        }
        Ok(())
    }

    pub async fn flush(&self) -> Result<(), Error> {
        let mut lock = match timeout(Duration::from_secs(10), self.conn.lock()).await {
            Ok(lock) => lock,
            Err(e) => {
                return Err(Error::Timeout(e));
            }
        };
        let conn = match &mut *lock {
            Some(conn) => conn,
            None => {
                return Err(Error::NotConnected);
            }
        };
        conn.flush().await
    }

    pub async fn state(&self) -> Result<PeerConnState, Error> {
        let mut lock = match timeout(Duration::from_secs(10), self.conn.lock()).await {
            Ok(lock) => lock,
            Err(e) => {
                return Err(Error::Timeout(e));
            }
        };
        let conn = match &mut *lock {
            Some(conn) => conn,
            None => {
                return Err(Error::NotConnected);
            }
        };
        Ok(conn.state)
    }

    pub async fn run_event_loop(&self) -> Result<(), PeerError> {
        // run event loop
        loop {
            if crate::DEBUG {
                println!("[debug] polling for peer {} message...", &self.info);
            }
            match self.read().await {
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

            // update interested state
            let msg_interest = if let Some(bitfield_peer) = self.bitfield.read().await.as_ref() {
                // compare peer bitfield with own bitfield
                let bitfield = self.torrent.pieces.as_bitfield();
                let bitfield_interesting = bitfield_peer.except(&bitfield);
                if bitfield_interesting.is_all_clear() {
                    Some(Message::NotInterested)
                } else {
                    Some(Message::Interested)
                }
            } else {
                None
            };

            if let Some(msg_interest) = msg_interest {
                // send message (NoOp = already same state)
                match self.write(msg_interest.clone()).await {
                    Ok(_) => {
                        if crate::DEBUG {
                            println!(
                                "[debug] updated peer {} interest: {:?}",
                                &self.info, msg_interest
                            );
                        }
                    }
                    Err(Error::NoOp) => {}
                    Err(e) => return Err(PeerError::WriteError(e)),
                };
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

    pub async fn connect_and_run_event_loop(self: Arc<Self>) -> Result<(), PeerError> {
        self.connect()
            .await
            .map_err(|e| PeerError::ConnectionError(e))?;

        // handshake with peer
        match self.handshake().await {
            Ok(_) => {
                if crate::DEBUG {
                    println!("[debug] connected to peer {}", &self.info);
                }
                // self.torrent.active_peers.fetch_add(1, Ordering::SeqCst);

                // if we have some pieces, send bitfield
                let bitfield = self.torrent.pieces.as_bitfield();
                if !bitfield.is_all_clear() {
                    if crate::DEBUG {
                        println!(
                            "[debug] sending bitfield to peer {}: {:?}",
                            &self.info, &bitfield
                        );
                    }
                    match self.write(Message::Bitfield(bitfield)).await {
                        Ok(_) => {
                            match self.run_event_loop().await {
                                Ok(_) => {
                                    if crate::DEBUG {
                                        println!("[debug] disconnected from peer {}", &self.info);
                                    }
                                }
                                Err(e) => {
                                    if crate::DEBUG {
                                        println!(
                                            "[debug] disconnected from peer {}: {:?}",
                                            &self.info, e
                                        );
                                    }
                                }
                            };
                        }
                        Err(e) => {
                            println!(
                                "[warning] unable to send our bitfield to peer {}: {:?}",
                                &self.info, e
                            );
                        }
                    }
                }

                // self.torrent.active_peers.fetch_sub(1, Ordering::SeqCst);
                if let Some(peer_bitfield) = self.bitfield.read().await.as_ref() {
                    let _ = self
                        .torrent
                        .pieces
                        .decrease_availability(peer_bitfield)
                        .await;
                }
            }
            Err(e) => {
                println!(
                    "[warning] unable to handshake with peer {}: {:?}",
                    &self.info, e
                );
            }
        }

        let mut peers = self.torrent.peers.write().await;
        if let Some(pos) = peers.iter().position(|x| x.info == self.info) {
            peers.remove(pos);
        }

        Ok(())
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info
    }
}
