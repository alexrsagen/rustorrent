use crate::{error::Error, peer::PeerInfo};
use crate::peer::PortRange;

use chashmap::CHashMap;
use chrono::{DateTime, Utc, Duration};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};

use rand::Rng;
use url::Url;

use std::{convert::Infallible, ops::Add};
use std::default::Default;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;

use super::announce::{AnnounceRequest, AnnounceResponse, Announce};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TrackerServerOptions {
    pub ip: IpAddr,
    pub port_range: PortRange,
}

impl Default for TrackerServerOptions {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port_range: PortRange::from(1024..=65535),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Hash)]
struct TrackerServerPeerKey {
    peer_id: [u8; 20],
    info_hash: [u8; 20],
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct TrackerServerPeer {
    info: PeerInfo,
    info_hash: [u8; 20],
    user_agent: Option<String>,
    key: Option<String>,
    expire: DateTime<Utc>,
    seed: bool,
}

async fn handle(
    server: TrackerHttpServer,
    addr: SocketAddr,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    server.handle(addr, req).await
}

#[derive(Debug, Clone)]
pub struct TrackerHttpServer {
    #[allow(unused)]
    opts: TrackerServerOptions,
    addr: SocketAddr,
    peers: CHashMap<TrackerServerPeerKey, TrackerServerPeer>,
}

impl TrackerHttpServer {
    pub fn new(opts: TrackerServerOptions) -> Self {
        let mut rng = rand::thread_rng();

        // get local bind address from provided port range
        let port_range: RangeInclusive<u16> = opts.port_range.into();
        let addr = SocketAddr::new(opts.ip, rng.gen_range(port_range));

        Self { opts, addr, peers: CHashMap::new() }
    }

    pub async fn run(&self) -> Result<(), Error> {
        // create and start hyper server
        let make_service = make_service_fn(move |conn: &AddrStream| {
            let server = self.clone();
            let addr = conn.remote_addr();
            let service = service_fn(move |req| handle(server.clone(), addr, req));
            async move { Ok::<_, Infallible>(service) }
        });
        Server::bind(&self.addr)
            .serve(make_service)
            .await
            .map_err(Error::Hyper)
    }

    async fn handle(
        &self,
        addr: SocketAddr,
        req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        let mut rng = rand::thread_rng();

        // parse and validate request parameters
        if req.uri().path() != "/announce" {
            return Ok(Response::builder().status(404).body(Body::empty()).unwrap());
        }
        if req.method() != Method::GET {
            return Ok(Response::builder().status(405).body(Body::empty()).unwrap());
        }
        let mut announce_req: AnnounceRequest = match Url::parse(req.uri().to_string().as_ref()) {
            Ok(endpoint) => {
                let mut query = endpoint.query_pairs();
                (&mut query).into()
            },
            Err(e) => {
                return Ok(Response::builder().status(400).header("Content-Type", "text/plain").body(AnnounceResponse::Failure("Bad Request".into()).into()).unwrap());
            },
        };
        if announce_req.peer_id.is_none() {
            return Ok(Response::builder().status(400).header("Content-Type", "text/plain").body(AnnounceResponse::Failure("Missing or invalid peer_id".into()).into()).unwrap());
        }
        if announce_req.port.is_none() {
            return Ok(Response::builder().status(400).header("Content-Type", "text/plain").body(AnnounceResponse::Failure("Missing or invalid port".into()).into()).unwrap());
        }
        if announce_req.info_hash.is_none() {
            return Ok(Response::builder().status(400).header("Content-Type", "text/plain").body(AnnounceResponse::Failure("Missing or invalid info_hash".into()).into()).unwrap());
        }
        if announce_req.ip.is_none() {
            announce_req.ip = Some(addr.ip());
        }

        // insert/update peer
        let key = TrackerServerPeerKey {
            peer_id: announce_req.peer_id.unwrap(),
            info_hash: announce_req.info_hash.unwrap(),
        };
        let info = PeerInfo::new(announce_req.peer_id, SocketAddr::new(announce_req.ip.unwrap(), announce_req.port.unwrap()));
        let user_agent = if crate::DEBUG {
            // only store user agent if debugging
            match req.headers().get("User-Agent") {
                Some(val) => val.to_str().ok().map(str::to_string),
                None => None,
            }
        } else {
            None
        };
        let expire = if announce_req.event == Some(String::from("stopped")) {
            Utc::now().add(Duration::seconds(-60))
        } else {
            Utc::now().add(Duration::seconds(300))
        };
        self.peers.upsert(key, || TrackerServerPeer {
            info,
            info_hash: announce_req.info_hash.unwrap(),
            user_agent: user_agent.clone(),
            key: announce_req.key.clone(),
            expire,
            seed: announce_req.left == Some(0),
        }, |peer| {
            // only update peer if key matches
            if peer.key == announce_req.key {
                peer.info = info;
                peer.user_agent = user_agent.clone();
                peer.expire = expire;
                peer.seed = announce_req.left == Some(0);
            }
        });

        // TODO: retire expired peers (expiry + 1 minute)

        // return bencoded peer list (excluding the announcing peer)
        Ok(Response::new(AnnounceResponse::Success(Announce {
            warning_message: None,
            interval: std::time::Duration::from_secs(rng.gen_range(300..=310)),
            min_interval: Some(std::time::Duration::from_secs(60)),
            tracker_id: None,
            complete: 0,   // TODO: get count of seeding peers
            incomplete: 0, // TODO: get count of non-seeding peers
            peers: vec![], // TODO: get Vec<PeerInfo> from peers, excluding announcing peer
        }).into()))
    }
}
