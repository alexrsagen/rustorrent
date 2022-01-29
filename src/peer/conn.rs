use super::TorrentPeerInfo;
use super::proto::{Handshake, Message};
use crate::error::Error;
use crate::client::Client;
use crate::torrent::metainfo::InfoHash;

use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use std::sync::Arc;
use std::convert::TryInto;
use std::default::Default;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[derive(Debug)]
pub enum EventLoopError {
    ConnectionError(Error),
    ReadError(Error),
    WriteError(Error),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PeerConnOptions {
    pub addr: SocketAddr,
    pub max_rx_len: usize, // max message length in bytes (not including length header)
    pub connect_timeout: Option<Duration>, // connection timeout
    pub rx_timeout: Option<Duration>, // read timeout
    pub tx_timeout: Option<Duration>, // write timeout
    pub keepalive_interval: Duration,
}

impl Default for PeerConnOptions {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            max_rx_len: 64 << 10, // 64 KiB
            connect_timeout: Some(Duration::from_secs(3)),
            rx_timeout: Some(Duration::from_secs(5)),
            tx_timeout: Some(Duration::from_secs(5)),
            keepalive_interval: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PeerConnState {
    pub rx_msg_count: usize,
    pub tx_msg_count: usize,
    pub peer_choking: bool,
    pub am_choking: bool,
    pub peer_interested: bool,
    pub am_interested: bool,
}

impl Default for PeerConnState {
    fn default() -> Self {
        Self {
            rx_msg_count: 0,
            tx_msg_count: 0,
            peer_choking: true,
            am_choking: true,
            peer_interested: false,
            am_interested: false,
        }
    }
}

#[derive(Debug)]
pub struct PeerConn {
    pub opts: PeerConnOptions,
    pub state: PeerConnState,
    peer: TorrentPeerInfo,
    rx: BufReader<tokio::net::tcp::OwnedReadHalf>,
    tx: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    last_rx: Option<DateTime<Utc>>,
    last_tx: Option<DateTime<Utc>>,
}

impl PeerConn {
    pub async fn connect(peer: TorrentPeerInfo) -> Result<Self, Error> {
        Self::connect_with_opts(peer, PeerConnOptions::default()).await
    }

    pub async fn connect_with_opts(peer: TorrentPeerInfo, opts: PeerConnOptions) -> Result<Self, Error> {
        let socket = match opts.addr.ip() {
            IpAddr::V4(_) => TcpSocket::new_v4()?,
            IpAddr::V6(_) => TcpSocket::new_v6()?,
        };
        socket.bind(opts.addr)?;
        let future = socket.connect(peer.addr_and_id.addr);
        let stream = if let Some(connect_timeout) = opts.connect_timeout {
            timeout(connect_timeout, future).await??
        } else {
            future.await?
        };
        Ok(Self::new_with_opts(stream, peer, opts))
    }

    pub fn new(stream: TcpStream, peer: TorrentPeerInfo) -> Self {
        Self::new_with_opts(stream, peer, PeerConnOptions::default())
    }

    pub fn new_with_opts(stream: TcpStream, peer: TorrentPeerInfo, opts: PeerConnOptions) -> Self {
        let (rx, tx) = stream.into_split();
        Self {
            opts,
            state: PeerConnState::default(),
            peer,
            rx: BufReader::with_capacity(opts.max_rx_len, rx),
            tx: BufWriter::new(tx),
            last_rx: None,
            last_tx: None,
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let future = self.rx.read_exact(buf);
        let n = if let Some(rx_timeout) = self.opts.rx_timeout {
            timeout(rx_timeout, future).await??
        } else {
            future.await?
        };
        self.last_rx = Some(Utc::now());
        Ok(n)
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        let future = self.tx.write_all(buf);
        if let Some(rx_timeout) = self.opts.rx_timeout {
            timeout(rx_timeout, future).await??;
        } else {
            future.await?;
        }
        self.last_tx = Some(Utc::now());
        Ok(())
    }

    pub async fn read_handshake(&mut self) -> Result<Handshake, Error> {
        let mut hbuf = Vec::with_capacity(68);
        // read handshake pstrlen
        hbuf.resize(1, 0);
        self.read_exact(&mut hbuf[0..1]).await?;
        // read rest of handshake
        hbuf.resize(1 + hbuf[0] as usize + 8 + 20 + 20, 0);
        self.read_exact(&mut hbuf[1..]).await?;
        hbuf.try_into()
    }

    pub async fn write_handshake(&mut self, handshake: &Handshake) -> Result<(), Error> {
        let hbuf: Vec<u8> = handshake.into();
        Ok(self.write_all(&hbuf).await?)
    }

    pub async fn read_msg(&mut self) -> Result<Message, Error> {
        // read length
        let mut lenbuf = [0u8; 4];
        self.read_exact(&mut lenbuf).await?;
        let len = u32::from_be_bytes(lenbuf) as usize;
        // check length
        if len == 0 {
            return Ok(Message::Keepalive);
        } else if len > self.opts.max_rx_len {
            // payload too large
            // read and discard remaining bytes from the connection
            // to avoid corruption on subsequent reads
            tokio::io::copy(&mut (&mut self.rx).take(len as u64), &mut tokio::io::sink()).await?;
            return Err(Error::MessageLengthInvalid);
        }
        // read message
        let mut mbuf = vec![0; len];
        self.read_exact(&mut mbuf).await?;
        Ok(mbuf.into())
    }

    pub async fn write_msg(&mut self, msg: Message) -> Result<(), Error> {
        let mbuf: Vec<u8> = msg.into();
        let len_bytes = (mbuf.len() as u32).to_be_bytes();
        self.write_all(&len_bytes).await?;
        self.write_all(&mbuf).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), Error> {
        Ok(self.tx.flush().await?)
    }

    pub fn duration_since_last_rx(&self) -> Duration {
        if let Some(last_rx) = self.last_rx {
            let now = Utc::now();
            (now - last_rx).to_std().unwrap_or_default()
        } else {
            Duration::new(0, 0)
        }
    }

    pub fn duration_since_last_tx(&self) -> Duration {
        if let Some(last_tx) = self.last_tx {
            let now = Utc::now();
            (now - last_tx).to_std().unwrap_or_default()
        } else {
            Duration::new(0, 0)
        }
    }

    pub async fn handshake(&mut self, client: Arc<Client>) -> Result<(), Error> {
        let torrent = match client.torrents.get(&self.peer.info_hash) {
            Some(torrent) => torrent,
            None => return Err(Error::InfoHashInvalid),
        };
        self.write_handshake(&torrent.handshake).await?;
        self.flush().await?;
        let handshake = self.read_handshake().await?;
        // check peer_id against known value, if known
        if let Some(peer_id) = self.peer.addr_and_id.id {
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
    pub async fn read(&mut self, client: Arc<Client>) -> Result<Message, Error> {
        let torrent = match client.torrents.get(&self.peer.info_hash) {
            Some(torrent) => torrent,
            None => return Err(Error::InfoHashInvalid),
        };
        let peer_bitfield = match torrent.peer_bitfields.get(&self.peer.addr_and_id) {
            Some(peer_bitfield) => peer_bitfield,
            None => return Err(Error::InfoHashInvalid),
        };
        let msg = self.read_msg().await?;
        self.state.rx_msg_count += 1;
        match msg {
            Message::InvalidId => Err(Error::MessageIdInvalid),
            Message::InvalidLength => Err(Error::MessageLengthInvalid),
            Message::Keepalive => Err(Error::MessageHandled),
            Message::Choke => {
                if crate::DEBUG {
                    println!("[debug] peer {} is choking", &self.peer.addr_and_id);
                }
                self.state.peer_choking = true;
                Err(Error::MessageHandled)
            }
            Message::Unchoke => {
                if crate::DEBUG {
                    println!("[debug] peer {} no longer choking", &self.peer.addr_and_id);
                }
                self.state.peer_choking = false;
                Err(Error::MessageHandled)
            }
            Message::Interested => {
                if crate::DEBUG {
                    println!("[debug] peer {} is interested", &self.peer.addr_and_id);
                }
                self.state.peer_interested = true;
                Err(Error::MessageHandled)
            }
            Message::NotInterested => {
                if crate::DEBUG {
                    println!("[debug] peer {} is no longer interested", &self.peer.addr_and_id);
                }
                self.state.peer_interested = false;
                Err(Error::MessageHandled)
            }
            Message::Have(index) => {
                if crate::DEBUG {
                    println!("[debug] peer {} has piece {}", &self.peer.addr_and_id, index);
                }
                peer_bitfield.set_bit(index as usize);
                torrent.pieces.increase_availability(&peer_bitfield).await?;
                Err(Error::MessageHandled)
            }
            Message::Bitfield(mut bitfield) => {
                if self.state.rx_msg_count != 1 {
                    return Err(Error::UnexpectedOrInvalidBitfield);
                }
                bitfield.resize(torrent.metainfo.info.piece_hashes.len());
                if bitfield.spare_bits_as_byte() != 0 {
                    return Err(Error::UnexpectedOrInvalidBitfield);
                }
                if crate::DEBUG {
                    println!("[debug] peer {} sent {:?}", &self.peer.addr_and_id, &bitfield);
                }
                torrent.pieces.increase_availability(&bitfield).await?;
                peer_bitfield.try_overwrite_with(&bitfield)?;
                Err(Error::MessageHandled)
            }
            Message::Piece(block) => {
                torrent
                    .pieces
                    .write_block(client.clone(), &self.peer, block)
                    .await?;
                Err(Error::MessageHandled)
            }
            Message::Request(request) => {
                if crate::DEBUG {
                    println!(
                        "[debug] peer {} requested block of piece {} (offset {}, length {})",
                        &self.peer.addr_and_id, request.index, request.begin, request.length
                    );
                }
                if self.state.am_choking {
                    // TODO: ignore piece request
                } else {
                    // TODO: handle piece request
                }
                Err(Error::MessageHandled)
            }
            Message::Cancel(request) => {
                if crate::DEBUG {
                    println!("[debug] peer {} cancelled request for block of piece {} (offset {}, length {})", &self.peer.addr_and_id, request.index, request.begin, request.length);
                }
                if self.state.am_choking {
                    // TODO: ignore piece cancel request
                } else {
                    // TODO: handle piece cancel request
                }
                Err(Error::MessageHandled)
            }
            msg => Ok(msg),
        }
    }

    pub async fn write(&mut self, msg: Message) -> Result<(), Error> {
        let mut am_choking = self.state.am_choking;
        let mut am_interested = self.state.am_interested;
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
                if self.state.peer_choking {
                    return Err(Error::PeerChoking);
                }
            }
            Message::Cancel(_) => {
                if self.state.peer_choking {
                    return Err(Error::PeerChoking);
                }
            }
            _ => {}
        }
        self.write_msg(msg).await?;
        self.state.tx_msg_count += 1;
        self.state.am_choking = am_choking;
        self.state.am_interested = am_interested;
        Ok(())
    }

    pub async fn keepalive(&mut self) -> Result<(), Error> {
        let keepalive_interval = self.opts.keepalive_interval - self.opts.tx_timeout.unwrap_or(Duration::from_secs(5));
        if self.duration_since_last_tx() > keepalive_interval {
            self.write(Message::Keepalive).await
        } else {
            Ok(())
        }
    }

    pub async fn run_event_loop(&mut self, client: Arc<Client>) -> Result<(), EventLoopError> {
        let torrent = match client.torrents.get(&self.peer.info_hash) {
            Some(torrent) => torrent,
            None => return Err(EventLoopError::ConnectionError(Error::InfoHashInvalid)),
        };
        let peer_bitfield = match torrent.peer_bitfields.get(&self.peer.addr_and_id) {
            Some(peer_bitfield) => peer_bitfield,
            None => return Err(EventLoopError::ConnectionError(Error::InfoHashInvalid)),
        };
        // run event loop
        loop {
            if crate::DEBUG {
                println!("[debug] polling for peer {} message...", &self.peer.addr_and_id);
            }
            match self.read(client.clone()).await {
                Ok(msg) => {
                    match msg {
                        Message::Port(dht_port) => {
                            if crate::DEBUG {
                                println!(
                                    "[debug] peer {} sent DHT port: {:?}",
                                    &self.peer.addr_and_id, dht_port
                                );
                            }
                            // TODO: DHT related, insert peer into "local routing table"
                        }
                        msg => {
                            if crate::DEBUG {
                                println!(
                                    "[debug] peer {} sent unhandled message: {:?}",
                                    &self.peer.addr_and_id, msg
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
                        &self.peer.addr_and_id, block_index, piece_index
                    );
                }
                Err(Error::InvalidPieceBlockMessage {
                    piece_index,
                    block_index,
                }) => {
                    println!("[warning] peer {} sent invalid block {} of piece {} (wrong begin or length)", &self.peer.addr_and_id, block_index, piece_index);
                }
                Err(Error::PieceHashInvalid { piece_index }) => {
                    println!(
                        "[warning] piece {} could not be verified and will be re-downloaded",
                        piece_index
                    );
                }
                Err(e) => return Err(EventLoopError::ReadError(e)),
            }

            // update interested state by comparing peer bitfield with torrent bitfield
            let bitfield = torrent.pieces.as_bitfield();
            let bitfield_interesting = peer_bitfield.except(&bitfield);
            let msg_interest = if bitfield_interesting.is_all_clear() {
                Message::NotInterested
            } else {
                Message::Interested
            };
            // send message (NoOp = already same state)
            if crate::DEBUG {
                println!(
                    "[debug] updating peer {} interest: {:?}",
                    &self.peer.addr_and_id, &msg_interest
                );
            }
            match self.write(msg_interest).await {
                Ok(_) => {}
                Err(Error::NoOp) => {}
                Err(e) => return Err(EventLoopError::WriteError(e)),
            }

            // TODO: choke/unchoke peer here, but make the decision elsewhere(?)
            // need to implement a choking/unchoking algorithm

            // TODO: implement disconnect: return Ok(state)

            if !self.state.peer_choking {
                // TODO: request pieces from peer
                // TODO: - pipelining and adaptive queueing (https://luminarys.com/posts/writing-a-bittorrent-client.html)
                // match self.write(Message::Request(req.clone())).await {
                // 	Ok(_) => {
                // 		// self.requests.push(req);
                // 	},
                // 	Err(e) => {
                // 		self.peer.torrent.req_queue.push(req);
                // 		return Err(EventLoopError::WriteError(e))
                // 	},
                // }
            }

            // keep connection alive
            self.keepalive()
                .await
                .map_err(|e| EventLoopError::WriteError(e))?;

            // flush all messages to peer
            self.flush().await.map_err(|e| EventLoopError::WriteError(e))?;

            // TODO: find and cancel timed out requests
        }
    }
}
