use super::port_range::PortRange;
use crate::bencode;
use crate::error::Error;

use rand::Rng;

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct PeerInfo {
    pub id: Option<[u8; 20]>,
    pub addr: SocketAddr,
}

impl PeerInfo {
    pub fn new(id: Option<[u8; 20]>, addr: SocketAddr) -> Self {
        Self { id, addr }
    }

    pub fn new_local(prefix: &'static str, ip: IpAddr, port_range: PortRange) -> Self {
        let mut rng = rand::thread_rng();

        // generate a new random ID
        let mut prefix = String::from(prefix);
        let id_rand: String = (&mut rng)
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(20 - prefix.len())
            .map(char::from)
            .collect();
        prefix.push_str(&id_rand);
        let id = Some(prefix.as_bytes().try_into().unwrap());

        // get local bind address from provided port range
        let port_range: RangeInclusive<u16> = port_range.into();
        let addr = SocketAddr::new(ip, rng.gen_range(port_range));

        Self::new(id, addr)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = match self.addr.ip() {
            IpAddr::V4(ip) => {
                let mut bytes = Vec::with_capacity(6);
                bytes.extend_from_slice(&ip.octets()[..]);
                bytes
            }
            IpAddr::V6(ip) => {
                let mut bytes = Vec::with_capacity(18);
                bytes.extend_from_slice(&ip.octets()[..]);
                bytes
            }
        };
        bytes.extend_from_slice(&self.addr.port().to_be_bytes()[..]);
        bytes
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.id {
            Some(v) => write!(f, "{} (ID {:?})", self.addr, String::from_utf8_lossy(&v)),
            None => write!(f, "{}", self.addr),
        }
    }
}

impl From<[u8; 6]> for PeerInfo {
    fn from(value: [u8; 6]) -> Self {
        Self {
            id: None,
            addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])),
                u16::from_be_bytes([value[4], value[5]]),
            ),
        }
    }
}

impl From<[u8; 18]> for PeerInfo {
    fn from(value: [u8; 18]) -> Self {
        Self::new(
            None,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([value[0], value[1]]),
                    u16::from_be_bytes([value[2], value[3]]),
                    u16::from_be_bytes([value[4], value[5]]),
                    u16::from_be_bytes([value[6], value[7]]),
                    u16::from_be_bytes([value[8], value[9]]),
                    u16::from_be_bytes([value[10], value[11]]),
                    u16::from_be_bytes([value[12], value[13]]),
                    u16::from_be_bytes([value[14], value[15]]),
                )),
                u16::from_be_bytes([value[16], value[17]]),
            ),
        )
    }
}

impl TryFrom<bencode::Dict> for PeerInfo {
    type Error = Error;
    fn try_from(mut dict: bencode::Dict) -> Result<Self, Self::Error> {
        let mut id: Option<[u8; 20]> = None;
        if let Some(bencode::Value::Bytes(v)) = dict.remove("peer id") {
            id = Some(
                v.try_into()
                    .map_err(|_| Error::ValueTypeMissingOrInvalid("peer id".into()))?,
            );
        }
        let ip: IpAddr;
        if let Some(bencode::Value::Bytes(v)) = dict.remove("ip") {
            ip = String::from_utf8(v)?.parse()?;
        } else {
            return Err(Error::ValueTypeMissingOrInvalid("ip".into()));
        }
        let port: u16;
        if let Some(bencode::Value::Int(v)) = dict.remove("port") {
            port = v as u16;
        } else {
            return Err(Error::ValueTypeMissingOrInvalid("port".into()));
        }
        Ok(Self::new(id, SocketAddr::new(ip, port)))
    }
}

impl TryFrom<bencode::Value> for PeerInfo {
    type Error = Error;
    fn try_from(value: bencode::Value) -> Result<Self, Self::Error> {
        match value {
            bencode::Value::Dict(dict) => dict.try_into(),
            bencode::Value::Invalid(e) => Err(Error::Bencode(e)),
            _ => Err(Error::ValueTypeMissingOrInvalid("peer".into())),
        }
    }
}

impl TryFrom<bencode::Value> for Vec<PeerInfo> {
    type Error = Error;
    fn try_from(value: bencode::Value) -> Result<Self, Self::Error> {
        match value {
            bencode::Value::Bytes(bytes) => {
                if bytes.len() % 6 != 0 {
                    return Err(Error::ValueLengthInvalid("peers".into()));
                }
                let mut peers = Vec::new();
                for i in 0..bytes.len() / 6 {
                    let start = i * 6;
                    let end = start + 6;
                    let peer_bytes: [u8; 6] = bytes[start..end]
                        .try_into()
                        .map_err(|_| Error::ValueLengthInvalid("peer".into()))?;
                    peers.push(peer_bytes.into());
                }
                Ok(peers)
            }
            bencode::Value::List(list) => {
                let mut peers = Vec::new();
                for peer in list {
                    peers.push(peer.try_into()?)
                }
                Ok(peers)
            }
            _ => Err(Error::ValueTypeMissingOrInvalid("peers".into())),
        }
    }
}

impl From<&PeerInfo> for bencode::Dict {
    fn from(value: &PeerInfo) -> Self {
        let mut dict = bencode::Dict::new();
        if let Some(id) = value.id {
            dict.insert("peer id".into(), bencode::Value::Bytes(id.to_vec()));
        }
        dict.insert(
            "ip".into(),
            bencode::Value::Bytes(value.addr.ip().to_string().as_bytes().to_vec()),
        );
        dict.insert("port".into(), bencode::Value::Int(value.addr.port() as i64));
        dict
    }
}

impl From<&PeerInfo> for bencode::Value {
    fn from(value: &PeerInfo) -> Self {
        bencode::Value::Dict(value.into())
    }
}

impl From<&Vec<PeerInfo>> for bencode::Value {
    fn from(value: &Vec<PeerInfo>) -> Self {
        bencode::Value::List(value.iter().map(|peer| peer.into()).collect())
    }
}
