use super::{PeerId, PortRange};
use crate::bencode;
use crate::http::public_ip::DualStackIpAddr;
use crate::error::Error;

use rand::Rng;

use std::{convert::{TryFrom, TryInto}, net::{SocketAddrV4, SocketAddrV6}, cmp::Ordering};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;

fn apply_mask(b: &mut [u8], mask: &[u8]) {
    for (b_item, mask_item) in b.iter_mut().zip(mask.iter()) {
        *b_item &= *mask_item;
    }
}

fn peer_priority(remote_addr: SocketAddr, local_ip: DualStackIpAddr, local_port: u16) -> Option<u32> {
    let local_addr = match remote_addr {
        SocketAddr::V4(_) => match local_ip {
            DualStackIpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, local_port)),
            DualStackIpAddr::V6(ip) => return None,
            DualStackIpAddr::Both{v4, v6} => SocketAddr::V4(SocketAddrV4::new(v4, local_port)),
        },
        SocketAddr::V6(remote_addr_v6) => match local_ip {
            DualStackIpAddr::V4(ip) => return None,
            DualStackIpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, local_port, remote_addr_v6.flowinfo(), remote_addr_v6.scope_id())),
            DualStackIpAddr::Both{v4, v6} => SocketAddr::V6(SocketAddrV6::new(v6, local_port, remote_addr_v6.flowinfo(), remote_addr_v6.scope_id())),
        },
    };

    if remote_addr.ip() == local_addr.ip() {
        let (e1, e2) = if remote_addr.port() > local_addr.port() {
            (&local_addr, &remote_addr)
        } else {
            (&remote_addr, &local_addr)
        };
        let mut buf = Vec::with_capacity(4);
        buf.extend_from_slice(&e1.port().to_be_bytes());
        buf.extend_from_slice(&e2.port().to_be_bytes());
        Some(crc32fast::hash(&buf))
    } else if let (SocketAddr::V6(remote_addr), SocketAddr::V6(local_addr)) = &(remote_addr, local_addr) {
        const V6_MASK: [[u8; 8]; 3] = [
            [ 0xff, 0xff, 0xff, 0xff, 0x55, 0x55, 0x55, 0x55 ],
            [ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x55, 0x55 ],
            [ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ],
        ];
        let (e1, e2) = if remote_addr > local_addr {
            (local_addr, remote_addr)
        } else {
            (remote_addr, local_addr)
        };
        let (mut b1, mut b2) = (e1.ip().octets(), e2.ip().octets());
        let mask = if b1[0..4].cmp(&b2[0..4]) == Ordering::Greater  {
            &V6_MASK[0]
        } else if b1[0..6].cmp(&b2[0..6]) == Ordering::Greater {
            &V6_MASK[1]
        } else {
            &V6_MASK[2]
        };
        apply_mask(&mut b1, mask);
        apply_mask(&mut b2, mask);
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&b1);
        buf.extend_from_slice(&b2);
        Some(crc32fast::hash(&buf))
    } else if let (SocketAddr::V4(remote_addr), SocketAddr::V4(local_addr)) = &(remote_addr, local_addr) {
        const V4_MASK: [[u8; 4]; 3] = [
            [ 0xff, 0xff, 0x55, 0x55 ],
            [ 0xff, 0xff, 0xff, 0x55 ],
            [ 0xff, 0xff, 0xff, 0xff ],
        ];
        let (e1, e2) = if remote_addr > local_addr {
            (local_addr, remote_addr)
        } else {
            (remote_addr, local_addr)
        };
        let (mut b1, mut b2) = (e1.ip().octets(), e2.ip().octets());
        let mask = if b1[0..2].cmp(&b2[0..2]) == Ordering::Greater  {
            &V4_MASK[0]
        } else if b1[0..3].cmp(&b2[0..3]) == Ordering::Greater {
            &V4_MASK[1]
        } else {
            &V4_MASK[2]
        };
        apply_mask(&mut b1, mask);
        apply_mask(&mut b2, mask);
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&b1);
        buf.extend_from_slice(&b2);
        Some(crc32fast::hash(&buf))
    } else {
        None
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct PeerAddrAndId {
    pub addr: SocketAddr,
    pub id: Option<PeerId>,
}

impl PeerAddrAndId {
    pub fn new(addr: SocketAddr, id: Option<PeerId>) -> Self {
        Self { addr, id }
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

        Self::new(addr, id)
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

    pub fn rank(&self, local_ip: DualStackIpAddr, local_port: u16) -> Option<u32> {
        peer_priority(self.addr, local_ip, local_port)
    }
}

impl fmt::Display for PeerAddrAndId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.id {
            Some(v) => write!(f, "{} (ID {:?})", self.addr, String::from_utf8_lossy(&v)),
            None => write!(f, "{}", self.addr),
        }
    }
}

impl From<[u8; 6]> for PeerAddrAndId {
    fn from(value: [u8; 6]) -> Self {
        Self::new(
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])),
                u16::from_be_bytes([value[4], value[5]]),
            ),
            None,
        )
    }
}

impl From<[u8; 18]> for PeerAddrAndId {
    fn from(value: [u8; 18]) -> Self {
        Self::new(
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
            None,
        )
    }
}

impl TryFrom<bencode::Dict> for PeerAddrAndId {
    type Error = Error;
    fn try_from(mut dict: bencode::Dict) -> Result<Self, Self::Error> {
        let mut id: Option<PeerId> = None;
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
        Ok(Self::new(SocketAddr::new(ip, port), id))
    }
}

impl TryFrom<bencode::Value> for PeerAddrAndId {
    type Error = Error;
    fn try_from(value: bencode::Value) -> Result<Self, Self::Error> {
        match value {
            bencode::Value::Dict(dict) => dict.try_into(),
            bencode::Value::Invalid(e) => Err(Error::Bencode(e)),
            _ => Err(Error::ValueTypeMissingOrInvalid("peer".into())),
        }
    }
}

impl TryFrom<bencode::Value> for Vec<PeerAddrAndId> {
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

impl From<&PeerAddrAndId> for bencode::Dict {
    fn from(value: &PeerAddrAndId) -> Self {
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

impl From<&PeerAddrAndId> for bencode::Value {
    fn from(value: &PeerAddrAndId) -> Self {
        bencode::Value::Dict(value.into())
    }
}

impl From<&Vec<PeerAddrAndId>> for bencode::Value {
    fn from(value: &Vec<PeerAddrAndId>) -> Self {
        bencode::Value::List(value.iter().map(|peer| peer.into()).collect())
    }
}
