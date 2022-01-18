use crate::error::Error;
use crate::bitfield::Bitfield;
use crate::tracker::announce::Announce;

use tokio::net::UdpSocket;
use sha1::{Sha1, Digest};
use rand::Rng;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

pub const MAGIC:           i64 = 0x41727101980;
pub const ACTION_CONNECT:  i32 = 0;
pub const ACTION_ANNOUNCE: i32 = 1;
pub const ACTION_SCRAPE:   i32 = 2;
pub const ACTION_ERROR:    i32 = 3;
pub const EVENT_NONE:      i32 = 0;
pub const EVENT_COMPLETED: i32 = 1;
pub const EVENT_STARTED:   i32 = 2;
pub const EVENT_STOPPED:   i32 = 3;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Request {
	pub connection_id: i64,
	pub action: i32,
	pub transaction_id: i32,
	pub data: RequestData,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequestAuth {
	username: String,
	password: Option<String>,
	passwd_hash: Option<[u8; 8]>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RequestData {
	Connect,
	Announce {
		info_hash: [u8; 20],
		peer_id: [u8; 20],
		downloaded: i64,
		left: i64,
		uploaded: i64,
		event: i32,
		ip_addr: Ipv4Addr,
		key: u32,
		num_want: i32,
		port: u16,
		// extensions: u16,
		auth: Option<RequestAuth>,
		request_string: Option<String>,
	},
	Scrape {
		info_hashes: Vec<[u8; 20]>,
	},
	Unknown,
}

impl From<&Request> for Vec<u8> {
	fn from(value: &Request) -> Self {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&value.connection_id.to_be_bytes()[..]);
		bytes.extend_from_slice(&value.action.to_be_bytes()[..]);
		bytes.extend_from_slice(&value.transaction_id.to_be_bytes()[..]);
		match &value.data {
			RequestData::Connect => {},
			RequestData::Announce {
				info_hash,
				peer_id,
				downloaded,
				left,
				uploaded,
				event,
				ip_addr,
				key,
				num_want,
				port,
				auth,
				request_string
			} => {
				bytes.extend_from_slice(&info_hash[..]);
				bytes.extend_from_slice(&peer_id[..]);
				bytes.extend_from_slice(&downloaded.to_be_bytes()[..]);
				bytes.extend_from_slice(&left.to_be_bytes()[..]);
				bytes.extend_from_slice(&uploaded.to_be_bytes()[..]);
				bytes.extend_from_slice(&event.to_be_bytes()[..]);
				bytes.extend_from_slice(&ip_addr.octets()[..]);
				bytes.extend_from_slice(&key.to_be_bytes()[..]);
				bytes.extend_from_slice(&num_want.to_be_bytes()[..]);
				bytes.extend_from_slice(&port.to_be_bytes()[..]);
				let mut extensions = Bitfield::new(16);
				if auth.is_some() { extensions.set_bit(0); }
				if request_string.is_some() { extensions.set_bit(1); }
				bytes.extend_from_slice(extensions.as_bytes());
				if let Some(v) = auth {
					let passwd_hash: [u8; 20] = Sha1::digest(&bytes).into();
					bytes.extend_from_slice(&(v.username.len() as i8).to_be_bytes()[..]);
					bytes.extend_from_slice(v.username.as_bytes());
					bytes.extend_from_slice(&passwd_hash[0..8]);
				}
				if let Some(v) = request_string {
					bytes.extend_from_slice(&(v.len() as i8).to_be_bytes()[..]);
					bytes.extend_from_slice(v.as_bytes());
				}
			},
			RequestData::Scrape { info_hashes } => {
				for info_hash in info_hashes {
					bytes.extend_from_slice(&info_hash[..]);
				}
			},
			RequestData::Unknown => {},
		};
		bytes
	}
}

impl TryFrom<&[u8]> for Request {
	type Error = Error;
	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		if bytes.len() < 16 {
			return Err(Error::MessageLengthInvalid);
		}
		let connection_id = i64::from_be_bytes(bytes[0..8].try_into().map_err(|_| Error::ValueLengthInvalid("connection_id".into()))?);
		let action = i32::from_be_bytes(bytes[8..12].try_into().map_err(|_| Error::ValueLengthInvalid("action".into()))?);
		let transaction_id = i32::from_be_bytes(bytes[12..16].try_into().map_err(|_| Error::ValueLengthInvalid("transaction_id".into()))?);
		let data = match action {
			ACTION_CONNECT => RequestData::Connect,
			ACTION_ANNOUNCE => {
				if bytes.len() < 98 {
					return Err(Error::MessageLengthInvalid);
				}
				let info_hash = bytes[16..36].try_into().map_err(|_| Error::ValueLengthInvalid("info_hash".into()))?;
				let peer_id = bytes[36..56].try_into().map_err(|_| Error::ValueLengthInvalid("peer_id".into()))?;
				let downloaded = i64::from_be_bytes(bytes[56..64].try_into().map_err(|_| Error::ValueLengthInvalid("downloaded".into()))?);
				let left = i64::from_be_bytes(bytes[64..72].try_into().map_err(|_| Error::ValueLengthInvalid("left".into()))?);
				let uploaded = i64::from_be_bytes(bytes[72..80].try_into().map_err(|_| Error::ValueLengthInvalid("uploaded".into()))?);
				let event = i32::from_be_bytes(bytes[80..84].try_into().map_err(|_| Error::ValueLengthInvalid("event".into()))?);
				let ip_addr: [u8; 4] = bytes[84..88].try_into().map_err(|_| Error::ValueLengthInvalid("ip_addr".into()))?;
				let ip_addr = ip_addr.into();
				let key = u32::from_be_bytes(bytes[88..92].try_into().map_err(|_| Error::ValueLengthInvalid("key".into()))?);
				let num_want = i32::from_be_bytes(bytes[92..96].try_into().map_err(|_| Error::ValueLengthInvalid("num_want".into()))?);
				let port = u16::from_be_bytes(bytes[96..98].try_into().map_err(|_| Error::ValueLengthInvalid("port".into()))?);
				let mut auth: Option<RequestAuth> = None;
				let mut request_string: Option<String> = None;
				if bytes.len() >= 100 {
					let extensions = Bitfield::try_from_bytes(bytes[98..100].to_vec(), 16)?;
					let mut i = 100;
					if extensions.get(0) {
						if bytes.len() < i {
							return Err(Error::MessageLengthInvalid);
						}
						let username_len = bytes[i] as usize;
						i += 1;
						if bytes.len() < i + username_len + 8 {
							return Err(Error::MessageLengthInvalid);
						}
						let username = String::from_utf8_lossy(&bytes[i..i+username_len]).to_string();
						i += username_len;
						let passwd_hash = Some(bytes[i..i+8].try_into().map_err(|_| Error::ValueLengthInvalid("passwd_hash".into()))?);
						i += 8;
						auth = Some(RequestAuth { username, password: None, passwd_hash });
					}
					if extensions.get(1) {
						if bytes.len() < i {
							return Err(Error::MessageLengthInvalid);
						}
						let request_string_len = bytes[i] as usize;
						i += 1;
						if bytes.len() < i + request_string_len {
							return Err(Error::MessageLengthInvalid);
						}
						// i += request_string_len;
						request_string = Some(String::from_utf8_lossy(&bytes[i..i+request_string_len]).to_string());
					}
				}
				RequestData::Announce {
					info_hash,
					peer_id,
					downloaded,
					left,
					uploaded,
					event,
					ip_addr,
					key,
					num_want,
					port,
					auth,
					request_string,
				}
			},
			ACTION_SCRAPE => {
				let info_hash_num = (bytes.len() - 16) / 20;
				let mut info_hashes = Vec::with_capacity(info_hash_num);
				for i in 0..info_hash_num {
					let start = 16 + i*20;
					let end = start+20;
					if bytes.len() < end {
						return Err(Error::MessageLengthInvalid);
					}
					info_hashes.push(bytes[start..end].try_into().map_err(|_| Error::ValueLengthInvalid("info_hash".into()))?);
				}
				RequestData::Scrape { info_hashes }
			},
			_ => RequestData::Unknown,
		};
		Ok(Self { connection_id, action, transaction_id, data })
	}
}

impl TryFrom<Vec<u8>> for Request {
	type Error = Error;
	fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
		(&data as &[u8]).try_into()
	}
}

impl Request {
	pub fn new_connect(transaction_id: i32) -> Self {
		Self {
			connection_id: MAGIC,
			action: ACTION_CONNECT,
			transaction_id,
			data: RequestData::Connect,
		}
	}
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ScrapeInfo {
	pub complete: i32,
	pub downloaded: i32,
	pub incomplete: i32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
	pub action: i32,
	pub transaction_id: i32,
	pub data: ResponseData,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ResponseData {
	Connect {
		connection_id: i64,
	},
	Announce(Announce),
	Scrape {
		info: Vec<ScrapeInfo>,
	},
	Error {
		error: String,
	},
	Unknown,
}

impl From<&Response> for Vec<u8> {
	fn from(value: &Response) -> Self {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&value.action.to_be_bytes()[..]);
		bytes.extend_from_slice(&value.transaction_id.to_be_bytes()[..]);
		match &value.data {
			ResponseData::Connect { connection_id } => {
				bytes.extend_from_slice(&connection_id.to_be_bytes()[..]);
			},
			ResponseData::Announce(announce) => {
				bytes.extend_from_slice(&(announce.interval.as_secs() as i64).to_be_bytes()[..]);
				bytes.extend_from_slice(&announce.incomplete.to_be_bytes()[..]);
				bytes.extend_from_slice(&announce.complete.to_be_bytes()[..]);
				for peer in &announce.peers {
					bytes.append(&mut peer.to_vec());
				}
			},
			ResponseData::Scrape { info } => {
				for entry in info {
					bytes.extend_from_slice(&entry.complete.to_be_bytes()[..]);
					bytes.extend_from_slice(&entry.downloaded.to_be_bytes()[..]);
					bytes.extend_from_slice(&entry.incomplete.to_be_bytes()[..]);
				}
			},
			ResponseData::Error { error } => {
				bytes.extend_from_slice(error.as_bytes());
			},
			ResponseData::Unknown => {},
		};
		bytes
	}
}

impl Response {
	pub fn try_from_ipv4(bytes: &[u8]) -> Result<Self, Error> {
		Self::try_from(bytes, std::mem::size_of::<Ipv4Addr>())
	}

	pub fn try_from_ipv6(bytes: &[u8]) -> Result<Self, Error> {
		Self::try_from(bytes, std::mem::size_of::<Ipv6Addr>())
	}

	fn try_from(bytes: &[u8], ip_len: usize) -> Result<Self, Error> {
		if bytes.len() < 8 {
			return Err(Error::MessageLengthInvalid);
		}
		let action = i32::from_be_bytes(bytes[0..4].try_into().map_err(|_| Error::ValueLengthInvalid("action".into()))?);
		let transaction_id = i32::from_be_bytes(bytes[4..8].try_into().map_err(|_| Error::ValueLengthInvalid("transaction_id".into()))?);
		let data = match action {
			ACTION_CONNECT => {
				if bytes.len() < 16 {
					return Err(Error::MessageLengthInvalid);
				}
				ResponseData::Connect {
					connection_id: i64::from_be_bytes(bytes[8..16].try_into().map_err(|_| Error::ValueLengthInvalid("connection_id".into()))?),
				}
			},
			ACTION_ANNOUNCE => {
				if bytes.len() < 20 {
					return Err(Error::MessageLengthInvalid);
				}
				let peer_len = ip_len + 2;
				let peer_num = (bytes.len() - 20) / peer_len;
				let mut peers = Vec::with_capacity(peer_num);
				for i in 0..peer_num {
					let start = 20 + i*peer_len;
					let end = start+peer_len;
					if bytes.len() < end {
						return Err(Error::MessageLengthInvalid);
					}
					if ip_len == 4 {
						let peer_bytes: [u8; 6] = bytes[start..end].try_into().map_err(|_| Error::ValueLengthInvalid("peer".into()))?;
						peers.push(peer_bytes.into());
					} else {
						let peer_bytes: [u8; 18] = bytes[start..end].try_into().map_err(|_| Error::ValueLengthInvalid("peer".into()))?;
						peers.push(peer_bytes.into());
					}
				}
				ResponseData::Announce(Announce {
					warning_message: None,
					interval: Duration::from_secs(i32::from_be_bytes(bytes[8..12].try_into().map_err(|_| Error::ValueLengthInvalid("interval".into()))?) as u64),
					min_interval: None,
					tracker_id: None,
					incomplete: i32::from_be_bytes(bytes[12..16].try_into().map_err(|_| Error::ValueLengthInvalid("leechers".into()))?) as i64,
					complete: i32::from_be_bytes(bytes[16..20].try_into().map_err(|_| Error::ValueLengthInvalid("seeders".into()))?) as i64,
					peers,
				})
			},
			ACTION_SCRAPE => {
				let info_len = std::mem::size_of::<ScrapeInfo>();
				let info_num = (bytes.len() - 8) / info_len;
				let mut info = Vec::with_capacity(info_num);
				for i in 0..info_num {
					let start = 8 + i*info_len;
					let end = start+info_len;
					if bytes.len() < end {
						return Err(Error::MessageLengthInvalid);
					}
					info.push(ScrapeInfo {
						complete: i32::from_be_bytes(bytes[start .. start+4].try_into().map_err(|_| Error::ValueLengthInvalid("complete".into()))?),
						downloaded: i32::from_be_bytes(bytes[start+4 .. start+8].try_into().map_err(|_| Error::ValueLengthInvalid("downloaded".into()))?),
						incomplete: i32::from_be_bytes(bytes[start+8 .. start+12].try_into().map_err(|_| Error::ValueLengthInvalid("incomplete".into()))?),
					});
				}
				ResponseData::Scrape { info }
			},
			ACTION_ERROR => {
				if bytes.len() < 8 {
					return Err(Error::MessageLengthInvalid);
				}
				let error = String::from_utf8_lossy(&bytes[8..]).to_string();
				ResponseData::Error { error }
			},
			_ => ResponseData::Unknown,
		};
		Ok(Self { action, transaction_id, data })
	}
}

#[derive(Debug)]
pub struct UdpConn {
	socket: UdpSocket,
	rx_buf: Vec<u8>,
	connection_id: i64,
}

impl UdpConn {
	pub async fn connect(addr: SocketAddr) -> Result<Self, Error> {
		// get local unspec address with same family as remote
		let local_addr = if addr.is_ipv4() {
			SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0)
		} else {
			SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), 0)
		};

		// bind and connect udp socket
		let socket = UdpSocket::bind(local_addr).await?;
		socket.connect(addr).await?;

		// create connection and perform connection handshake
		let mut conn = Self {
			socket,
			rx_buf: vec![0; 65508],
			connection_id: MAGIC
		};

		// perform connect request
		let res = conn.perform_req(&conn.new_request(RequestData::Connect)).await?;

		// handle response
		match res.data {
			ResponseData::Connect { connection_id } => {
				if connection_id == MAGIC {
					// should never happen, unless a tracker is evil
					Err(Error::NotConnected)
				} else {
					conn.connection_id = connection_id;
					Ok(conn)
				}
			},
			_ => Err(Error::NotConnected),
		}
	}

	pub fn new_request(&self, data: RequestData) -> Request {
		Request {
			connection_id: self.connection_id,
			action: match data {
				RequestData::Announce { .. } => ACTION_ANNOUNCE,
				RequestData::Connect => ACTION_CONNECT,
				RequestData::Scrape { .. } => ACTION_SCRAPE,
				RequestData::Unknown => ACTION_ERROR,
			},
			transaction_id: rand::thread_rng().gen(),
			data
		}
	}

	pub async fn read_res(&mut self) -> Result<Response, Error> {
		let len = self.socket.recv(&mut self.rx_buf).await?;
		if self.socket.local_addr()?.is_ipv4() {
			Response::try_from_ipv4(&self.rx_buf[..len])
		} else {
			Response::try_from_ipv6(&self.rx_buf[..len])
		}
	}

	pub async fn write_req(&mut self, req: &Request) -> Result<(), Error> {
		let bytes: Vec<u8> = req.into();
		self.socket.send(&bytes).await?;
		Ok(())
	}

	pub async fn perform_req(&mut self, req: &Request) -> Result<Response, Error> {
		// send request and recv connect response
		self.write_req(req).await?;
		let res = self.read_res().await?;

		// check for error
		if let ResponseData::Error { error } = res.data {
			return Err(Error::TrackerError(error));
		}
		// check action match
		if res.action != req.action {
			return Err(Error::ActionInvalid);
		}
		// check transaction id match
		if res.transaction_id != req.transaction_id {
			return Err(Error::TransactionIdInvalid);
		}

		Ok(res)
	}
}