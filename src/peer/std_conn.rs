use crate::error::Error;
use crate::peer::proto::{Message, Handshake};

use std::io::{self, Read, Write, BufReader, BufWriter};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::convert::{TryFrom, TryInto};
use std::default::Default;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Options {
	pub max_rx_len: usize, // max message length in bytes (not including length header)
	pub rx_timeout: Option<Duration>, // read timeout
	pub tx_timeout: Option<Duration>, // write timeout
	pub connect_timeout: Option<Duration>, // connection timeout
}

impl Default for Options {
	fn default() -> Self {
		Self {
			max_rx_len: 64 << 10, // 64 KiB
			connect_timeout: Some(Duration::from_secs(3)),
			rx_timeout: Some(Duration::from_secs(10)),
			tx_timeout: Some(Duration::from_secs(10)),
		}
	}
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Progress {
	remaining: usize,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum State {
	Ready(),
	InProgress(Progress),
}

#[derive(Debug)]
pub struct Conn {
	opts: Options,
	rx: BufReader<TcpStream>,
	tx: BufWriter<TcpStream>,
	rx_state: State,
	tx_state: State,
}

impl TryFrom<TcpStream> for Conn {
	type Error = Error;
	fn try_from(stream: TcpStream) -> Result<Self, Error> {
		Self::new(stream)
	}
}

impl Conn {
	pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, Error> {
		Self::connect_with_opts(addr, Options::default())
	}

	pub fn connect_with_opts<A: ToSocketAddrs>(addr: A, opts: Options) -> Result<Self, Error> {
		let stream = if let Some(connect_timeout) = opts.connect_timeout {
			TcpStream::connect_timeout(addr, opts.connect_timeout)?;
		} else {
			TcpStream::connect(addr)?;
		}
		stream.set_write_timeout(opts.tx_timeout)?;
		stream.set_read_timeout(opts.rx_timeout)?;
		Self::new_with_opts(stream, opts)
	}

	pub fn new(stream: TcpStream) -> Result<Self, Error> {
		Self::new_with_opts(stream, Options::default())
	}

	pub fn new_with_opts(stream: TcpStream, opts: Options) -> Result<Self, Error> {
		let rx = BufReader::with_capacity(opts.max_rx_len, stream.try_clone()?);
		let tx = BufWriter::new(stream);
		Ok(Self {
			opts,
			rx,
			tx,
			rx_state: State::Ready(),
			tx_state: State::Ready(),
		})
	}

	pub fn into_stream(self) -> Result<TcpStream, Error> {
		Ok(self.tx.into_inner().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?)
	}

	pub fn shutdown(self, how: Shutdown) -> Result<(), Error> {
		Ok(self.into_stream()?.shutdown(how)?)
	}

	pub fn read_handshake(&mut self) -> Result<Handshake, Error> {
		let mut handshake_bytes = Vec::with_capacity(49);
		self.rx.by_ref().take(1).read_to_end(&mut handshake_bytes)?;
		if handshake_bytes.len() < 1 {
			return Err(Error::ValueLengthInvalid("handshake".into()));
		}
		self.rx.by_ref().take(handshake_bytes[0]as u64 + 8 + 20 + 20).read_to_end(&mut handshake_bytes)?;
		handshake_bytes.try_into()
	}

	pub fn write_handshake(&mut self, handshake: &Handshake) -> Result<(), Error> {
		let msg_bytes: Vec<u8> = handshake.into();
		Ok(self.tx.write_all(&msg_bytes)?)
	}

	pub fn read_msg(&mut self) -> Result<Message, Error> {
		let mut msg_bytes = Vec::new();
		self.read_to_end(&mut msg_bytes)?;
		Ok(msg_bytes.into())
	}

	pub fn write_msg(&mut self, msg: &Message) -> Result<(), Error> {
		if let Message::Invalid(e) = msg {
			return Err(Error::MessageInvalid());
		}
		let msg_bytes: Vec<u8> = msg.into();
		Ok(self.write_all(&msg_bytes)?)
	}
}

impl Read for Conn {
	fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
		match &mut self.rx_state {
			State::Ready() => {
				// read length
				let mut len_bytes = [0u8; 4];
				self.rx.read_exact(&mut len_bytes)?;
				let mut remaining = u32::from_be_bytes(len_bytes) as usize;
				// check length
				if remaining > self.opts.max_rx_len {
					// payload too large
					// read and discard remaining bytes from the connection
					// to avoid corruption on subsequent reads
					io::copy(&mut self.rx.by_ref().take(remaining as u64), &mut io::sink())?;
					return Err(io::Error::new(io::ErrorKind::InvalidData, Error::MessageLengthInvalid()));
				}
				// return if length is zero
				if remaining == 0 {
					return Ok(0);
				}
				let read_n = self.rx.by_ref().take(remaining as u64).read(&mut buf)?;
				// update read state
				if read_n > remaining {
					remaining = 0;
				} else {
					remaining -= read_n;
				}
				self.rx_state = State::InProgress(Progress{remaining});
				Ok(read_n)
			},
			State::InProgress(progress) => {
				if progress.remaining == 0 {
					self.rx_state = State::Ready();
					return Ok(0);
				}
				// read stream to buf
				let read_n = self.rx.by_ref().take(progress.remaining as u64).read(&mut buf)?;
				// update read state
				if read_n > progress.remaining {
					progress.remaining = 0;
				} else {
					progress.remaining -= read_n;
				}
				if progress.remaining == 0 {
					self.rx_state = State::Ready();
				}
				Ok(read_n)
			},
		}
	}
}

impl Write for Conn {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		match &mut self.tx_state {
			State::Ready() => {
				// write buf length as big-endian u32
				let len = buf.len();
				let len_bytes = (len as u32).to_be_bytes();
				self.tx.write_all(&len_bytes)?;
				// update write state
				self.tx_state = State::InProgress(Progress{remaining: len});
				self.write(buf)
			},
			State::InProgress(progress) => {
				// write buf to stream
				let written_n = self.tx.write(buf)?;
				// update write state
				progress.remaining -= written_n;
				if progress.remaining == 0 {
					self.tx_state = State::Ready();
				}
				Ok(written_n)
			},
		}
	}

	fn flush(&mut self) -> io::Result<()> {
		self.tx.flush()
	}
}