use crate::error::Error;
use crate::peer::proto::{Message, Handshake};

use tokio::io::{BufReader, BufWriter, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpSocket};
use tokio::time::timeout;
use chrono::{DateTime, Utc};

use std::convert::TryInto;
use std::default::Default;
use std::time::Duration;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

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
	rx: BufReader<tokio::net::tcp::OwnedReadHalf>,
	tx: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
	last_rx: Option<DateTime<Utc>>,
	last_tx: Option<DateTime<Utc>>,
}

impl From<TcpStream> for PeerConn {
	fn from(stream: TcpStream) -> Self {
		Self::new(stream)
	}
}

impl PeerConn {
	pub async fn connect(addr: SocketAddr) -> Result<Self, Error> {
		Self::connect_with_opts(addr, PeerConnOptions::default()).await
	}

	pub async fn connect_with_opts(addr: SocketAddr, opts: PeerConnOptions) -> Result<Self, Error> {
		let socket = match opts.addr.ip() {
			IpAddr::V4(_) => TcpSocket::new_v4()?,
			IpAddr::V6(_) => TcpSocket::new_v6()?,
		};
		socket.bind(opts.addr)?;
		let future = socket.connect(addr);
		let stream = if let Some(connect_timeout) = opts.connect_timeout {
			timeout(connect_timeout, future).await??
		} else {
			future.await?
		};
		Ok(Self::new_with_opts(stream, opts))
	}

	pub fn new(stream: TcpStream) -> Self {
		Self::new_with_opts(stream, PeerConnOptions::default())
	}

	pub fn new_with_opts(stream: TcpStream, opts: PeerConnOptions) -> Self {
		let (rx, tx) = stream.into_split();
		Self {
			opts,
			rx: BufReader::with_capacity(opts.max_rx_len, rx),
			tx: BufWriter::new(tx),
			last_rx: None,
			last_tx: None,
			state: PeerConnState::default()
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
}