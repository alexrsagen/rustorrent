#[derive(Debug)]
pub enum TrackerProto {
    Tcp,
    Udp,
    Unknown,
    Other(String),
}

#[derive(Debug)]
pub enum PeerProto {
    BitTorrent,
    Unknown,
    Other(String),
}

#[derive(Debug)]
pub enum HttpProto {
    Http,
    Https,
    Unknown,
    Other(String),
}

#[derive(Debug)]
pub enum InvalidProto {
    Tracker(TrackerProto),
    Peer(PeerProto),
    Http(HttpProto),
}

impl std::fmt::Display for InvalidProto {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Tracker(p) => write!(f, "invalid tracker protocol: {:?}", p),
            Self::Peer(p) => write!(f, "invalid peer protocol: {:?}", p),
            Self::Http(p) => write!(f, "invalid http protocol: {:?}", p),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Bencode(crate::bencode::Error),
    Hyper(hyper::Error),
    Http(hyper::http::Error),
    ToStrError(hyper::header::ToStrError),
    HttpEncodingInvalid,
    Io(std::io::Error),
    ValueTypeMissingOrInvalid(String),
    ValueLengthInvalid(String),
    Utf8Invalid(std::string::FromUtf8Error),
    IpInvalid(std::net::AddrParseError),
    PortInvalid(std::num::ParseIntError),
    UriInvalid(hyper::http::uri::InvalidUri),
    ProtoInvalid(InvalidProto),
    ResolveError(Box<trust_dns_resolver::error::ResolveError>),
    JoinError(tokio::task::JoinError),
    Timeout(tokio::time::error::Elapsed),
    PeerIdInvalid,
    InfoHashInvalid,
    PieceHashInvalid {
        piece_index: usize,
    },
    MessageHandled,
    MessageIdInvalid,
    MessageLengthInvalid,
    MessageInvalid,
    TransactionIdInvalid,
    ActionInvalid,
    TrackerError(String),
    AnnounceFailed(String),
    PublicIpLookupFailed(String),
    UnexpectedOrInvalidBitfield,
    UnsolicitedPieceBlockMessage {
        piece_index: usize,
        block_index: usize,
    },
    InvalidPieceBlockMessage {
        piece_index: usize,
        block_index: usize,
    },
    NotConnected,
    NoData,
    InvalidCommand,
    PeerChoking,
    NoOp,
    OutOfRange,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Bencode(e) => write!(f, "{}", e),
            Error::ValueTypeMissingOrInvalid(value) => {
                write!(f, "value {:?} missing or has invalid type", value)
            }
            Error::ValueLengthInvalid(value) => write!(f, "value {:?} has invalid length", value),
            Error::Utf8Invalid(e) => write!(f, "invalid UTF-8 encoding: {}", e),
            Error::IpInvalid(e) => write!(f, "invalid IP address: {}", e),
            Error::PortInvalid(e) => write!(f, "invalid port: {}", e),
            Error::UriInvalid(e) => write!(f, "invalid URI: {}", e),
            Error::ProtoInvalid(e) => write!(f, "{}", e),
            Error::ResolveError(e) => write!(f, "unable to resolve address: {}", e),
            Error::Timeout(e) => write!(f, "timed out: {}", e),
            Error::TrackerError(error) => write!(f, "tracker returned error: {}", error),
            Error::AnnounceFailed(reason) => write!(f, "announce failed: {}", reason),
            Error::PublicIpLookupFailed(reason) => write!(f, "public IP lookup failed: {}", reason),
            e => write!(f, "{:?}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        Self::new(std::io::ErrorKind::Other, e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<crate::bencode::Error> for Error {
    fn from(e: crate::bencode::Error) -> Self {
        Self::Bencode(e)
    }
}
impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Self::Hyper(e)
    }
}
impl From<hyper::http::Error> for Error {
    fn from(e: hyper::http::Error) -> Self {
        Self::Http(e)
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8Invalid(e)
    }
}
impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Self::IpInvalid(e)
    }
}
impl From<hyper::http::uri::InvalidUri> for Error {
    fn from(e: hyper::http::uri::InvalidUri) -> Self {
        Self::UriInvalid(e)
    }
}
impl From<trust_dns_resolver::error::ResolveError> for Error {
    fn from(e: trust_dns_resolver::error::ResolveError) -> Self {
        Self::ResolveError(e.into())
    }
}
impl From<tokio::time::error::Elapsed> for Error {
    fn from(e: tokio::time::error::Elapsed) -> Self {
        Self::Timeout(e)
    }
}
impl From<hyper::header::ToStrError> for Error {
    fn from(e: hyper::header::ToStrError) -> Self {
        Self::ToStrError(e)
    }
}
impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::JoinError(e)
    }
}
