use crate::error::{Error, InvalidProto, PeerProto};
use crate::bitfield::Bitfield;

use std::convert::{From, TryFrom, TryInto};

pub const PSTR: &str = "BitTorrent protocol";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Handshake {
	pub pstr: String,
	pub reserved: Bitfield,
	pub info_hash: [u8; 20],
	pub peer_id: [u8; 20],
}

impl Handshake {
	pub fn new(info_hash: &[u8; 20], peer_id: &[u8; 20]) -> Self {
		Self {
			pstr: String::from(PSTR),
			reserved: Bitfield::new(8 * 8),
			info_hash: *info_hash,
			peer_id: *peer_id,
		}
	}
}

impl TryFrom<&[u8]> for Handshake {
	type Error = Error;
	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		if data.len() < 49 {
			return Err(Error::MessageLengthInvalid);
		}
		let mut i = 0;
		let pstrlen = data[i] as usize;
		i += 1;
		if data.len() < 49 + pstrlen {
			return Err(Error::MessageLengthInvalid);
		}
		let pstr = String::from_utf8(data[i..i+pstrlen].to_vec())?;
		if pstr != PSTR {
			return Err(Error::ProtoInvalid(InvalidProto::Peer(PeerProto::Other(pstr))));
		}
		i += pstrlen;
		let reserved = Bitfield::try_from_bytes(data[i..i+8].to_vec(), 64)?;
		i += 8;
		let info_hash = data[i..i+20].try_into().map_err(|_| Error::MessageLengthInvalid)?;
		i += 20;
		let peer_id = data[i..i+20].try_into().map_err(|_| Error::MessageLengthInvalid)?;
		Ok(Self {pstr, reserved, info_hash, peer_id})
	}
}

impl TryFrom<Vec<u8>> for Handshake {
	type Error = Error;
	fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
		(&data as &[u8]).try_into()
	}
}

impl From<&Handshake> for Vec<u8> {
	fn from(value: &Handshake) -> Self {
		let mut msg = Vec::from([value.pstr.len() as u8]);
		msg.extend(value.pstr.as_bytes().iter());
		msg.extend(value.reserved.as_bytes().iter());
		msg.extend(value.info_hash.iter());
		msg.extend(value.peer_id.iter());
		msg
	}
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Request {
	pub index: u32,
	pub begin: u32,
	pub length: u32,
}

impl From<&[u8]> for Request {
	fn from(data: &[u8]) -> Self {
		Self {
			index: u32::from_be_bytes(data[0..4].try_into().unwrap()),
			begin: u32::from_be_bytes(data[4..8].try_into().unwrap()),
			length: u32::from_be_bytes(data[8..12].try_into().unwrap()),
		}
	}
}

impl From<Vec<u8>> for Request {
	fn from(data: Vec<u8>) -> Self {
		(&data as &[u8]).into()
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PieceBlock {
	pub index: u32,
	pub begin: u32,
	pub data: Vec<u8>,
}

impl From<&[u8]> for PieceBlock {
	fn from(data: &[u8]) -> Self {
		Self {
			index: u32::from_be_bytes(data[0..4].try_into().unwrap()),
			begin: u32::from_be_bytes(data[4..8].try_into().unwrap()),
			data: data[8..].to_vec(),
		}
	}
}

impl From<Vec<u8>> for PieceBlock {
	fn from(data: Vec<u8>) -> Self {
		(&data as &[u8]).into()
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Message {
	InvalidId,
	InvalidLength,
	Keepalive,          // <len=0000>
	Choke,              // <len=0001>  <id=0>
	Unchoke,            // <len=0001>  <id=1>
	Interested,         // <len=0001>  <id=2>
	NotInterested,      // <len=0001>  <id=3>
	Have(u32),          // <len=0005>  <id=4><piece index>
	Bitfield(Bitfield), // <len=0001+X><id=5><bitfield>
	Request(Request),   // <len=0013>  <id=6><index><begin><length>
	Piece(PieceBlock),       // <len=0009+X><id=7><index><begin><block>
	Cancel(Request),    // <len=0013>  <id=8><index><begin><length>
	Port(u16),          // <len=0003>  <id=9><listen-port>
}

impl Message {
	pub const ID_CHOKE:         u8 = 0;
	pub const ID_UNCHOKE:       u8 = 1;
	pub const ID_INTERESTED:    u8 = 2;
	pub const ID_NOTINTERESTED: u8 = 3;
	pub const ID_HAVE:          u8 = 4;
	pub const ID_BITFIELD:      u8 = 5;
	pub const ID_REQUEST:       u8 = 6;
	pub const ID_PIECE:         u8 = 7;
	pub const ID_CANCEL:        u8 = 8;
	pub const ID_PORT:          u8 = 9;
}

impl From<&[u8]> for Message {
	fn from(bytes: &[u8]) -> Self {
		if bytes.is_empty() {
			// no message ID means keepalive
			return Self::Keepalive;
		}
		let message_id = bytes[0];
		match message_id {
			Self::ID_CHOKE => Self::Choke,
			Self::ID_UNCHOKE => Self::Unchoke,
			Self::ID_INTERESTED => Self::Interested,
			Self::ID_NOTINTERESTED => Self::NotInterested,
			Self::ID_HAVE => {
				if bytes.len() != 5 {
					return Self::InvalidLength;
				}
				Self::Have(u32::from_be_bytes(bytes[1..5].try_into().unwrap()))
			},
			Self::ID_BITFIELD => Self::Bitfield(Bitfield::from_bytes(bytes[1..].to_vec())),
			Self::ID_REQUEST => {
				if bytes.len() != 13 { return Self::InvalidLength; }
				Self::Request(bytes[1..13].into())
			},
			Self::ID_PIECE => {
				if bytes.len() < 9 { return Self::InvalidLength; }
				Self::Piece(bytes[1..].into())
			},
			Self::ID_CANCEL => {
				if bytes.len() != 13 { return Self::InvalidLength; }
				Self::Cancel(bytes[1..13].into())
			},
			Self::ID_PORT => {
				if bytes.len() != 3 { return Self::InvalidLength; }
				Self::Port(u16::from_be_bytes(bytes[1..3].try_into().unwrap()))
			},
			_ => Self::InvalidId,
		}
	}
}

impl From<Vec<u8>> for Message {
	fn from(value: Vec<u8>) -> Self {
		(&value as &[u8]).into()
	}
}

impl From<Message> for Vec<u8> {
	fn from(value: Message) -> Self {
		let mut bytes = Vec::new();
		match value {
			Message::InvalidId => {},
			Message::InvalidLength => {},
			Message::Keepalive => {},
			Message::Choke => { bytes.push(Message::ID_CHOKE); },
			Message::Unchoke => { bytes.push(Message::ID_UNCHOKE); },
			Message::Interested => { bytes.push(Message::ID_INTERESTED); },
			Message::NotInterested => { bytes.push(Message::ID_NOTINTERESTED); },
			Message::Have(v) => {
				bytes.push(Message::ID_HAVE);
				bytes.extend(v.to_be_bytes().iter());
			},
			Message::Bitfield(v) => {
				bytes.push(Message::ID_BITFIELD);
				bytes.extend(v.as_bytes().iter());
			},
			Message::Request(v) => {
				bytes.push(Message::ID_REQUEST);
				bytes.extend(v.index.to_be_bytes().iter());
				bytes.extend(v.begin.to_be_bytes().iter());
				bytes.extend(v.length.to_be_bytes().iter());
			},
			Message::Piece(v) => {
				bytes.push(Message::ID_PIECE);
				bytes.extend(v.index.to_be_bytes().iter());
				bytes.extend(v.begin.to_be_bytes().iter());
				bytes.extend(v.data.iter());
			},
			Message::Cancel(v) => {
				bytes.push(Message::ID_CANCEL);
				bytes.extend(v.index.to_be_bytes().iter());
				bytes.extend(v.begin.to_be_bytes().iter());
				bytes.extend(v.length.to_be_bytes().iter());
			},
			Message::Port(v) => {
				bytes.push(Message::ID_PORT);
				bytes.extend(v.to_be_bytes().iter());
			},
		}
		bytes
	}
}