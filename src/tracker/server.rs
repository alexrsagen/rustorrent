use crate::error::Error;
use crate::peer::{PeerInfo, PortRange};

use super::announce::{Announce, AnnounceEvent, AnnounceKey, AnnounceRequest, AnnounceResponse};

use chashmap::CHashMap;
use chrono::{DateTime, Duration, Utc};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};

use rand::Rng;

use std::convert::Infallible;
use std::default::Default;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::{Add, RangeInclusive};
use std::str::FromStr;
use std::sync::Arc;

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
    key: Option<AnnounceKey>,
    expire: DateTime<Utc>,
    seed: bool,
}

#[derive(Debug)]
pub struct TrackerHttpServer {
    #[allow(unused)]
    opts: TrackerServerOptions,
    addr: SocketAddr,
    peers: CHashMap<TrackerServerPeerKey, TrackerServerPeer>,
}

impl TrackerHttpServer {
    pub async fn run(opts: TrackerServerOptions) -> Result<(), Error> {
        let mut rng = rand::thread_rng();

        // get local bind address from provided port range
        let port_range: RangeInclusive<u16> = opts.port_range.into();
        let addr = SocketAddr::new(opts.ip, rng.gen_range(port_range));

        // create tracker server
        let server = &Arc::new(Self {
            opts,
            addr,
            peers: CHashMap::new(),
        });

        // create and start hyper server
        let make_service = make_service_fn(move |conn: &AddrStream| {
            let server = server.clone();
            let addr = conn.remote_addr();
            let service = service_fn(move |req| handle(server.clone(), addr, req));
            async move { Ok::<_, Infallible>(service) }
        });
        Server::bind(&server.addr)
            .serve(make_service)
            .await
            .map_err(Error::Hyper)
    }
}

fn announce_failure(reason: &str) -> Response<Body> {
    Response::builder()
        .status(400)
        .header("Content-Type", "text/plain")
        .body(AnnounceResponse::Failure(reason.into()).into())
        .unwrap()
}

async fn handle(
    server: Arc<TrackerHttpServer>,
    addr: SocketAddr,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    // parse and validate request parameters
    if req.uri().path() != "/announce" {
        return Ok(Response::builder().status(404).body(Body::empty()).unwrap());
    }
    if req.method() != Method::GET {
        return Ok(Response::builder().status(405).body(Body::empty()).unwrap());
    }
    let mut announce_req: AnnounceRequest = if let Some(query) = req.uri().query() {
        AnnounceRequest::from_str(query).unwrap()
    } else {
        return Ok(announce_failure("Bad Request"));
    };
    if announce_req.peer_id.is_none() {
        if crate::DEBUG {
            println!("[debug] announce failure: Missing or invalid peer_id");
        }
        return Ok(announce_failure("Missing or invalid peer_id"));
    }
    if announce_req.port.is_none() {
        if crate::DEBUG {
            println!("[debug] announce failure: Missing or invalid port");
        }
        return Ok(announce_failure("Missing or invalid port"));
    }
    if announce_req.info_hash.is_none() {
        if crate::DEBUG {
            println!("[debug] announce failure: Missing or invalid info_hash");
        }
        return Ok(announce_failure("Missing or invalid info_hash"));
    }
    if announce_req.ip.is_none() {
        announce_req.ip = Some(addr.ip());
    }

    let mut rng = rand::thread_rng();
    let now = Utc::now();

    // insert/update peer
    let key = TrackerServerPeerKey {
        peer_id: announce_req.peer_id.unwrap(),
        info_hash: announce_req.info_hash.unwrap(),
    };
    let info = PeerInfo::new(
        announce_req.peer_id,
        SocketAddr::new(announce_req.ip.unwrap(), announce_req.port.unwrap()),
    );
    if crate::DEBUG {
        println!("[debug] announce from peer {}", &info);
    }
    let user_agent = if crate::DEBUG {
        // only store user agent if debugging
        match req.headers().get("User-Agent") {
            Some(val) => val.to_str().ok().map(str::to_string),
            None => None,
        }
    } else {
        None
    };
    let expire = if announce_req.event == Some(AnnounceEvent::Stopped) {
        now.add(Duration::seconds(-60))
    } else {
        now.add(Duration::seconds(300))
    };
    server.peers.upsert(
        key,
        || TrackerServerPeer {
            info,
            info_hash: announce_req.info_hash.unwrap(),
            user_agent: user_agent.clone(),
            key: announce_req.key.clone(),
            expire,
            seed: announce_req.left == Some(0),
        },
        |peer| {
            // only update peer if key matches
            if peer.key == announce_req.key {
                peer.info = info;
                peer.user_agent = user_agent.clone();
                peer.expire = expire;
                peer.seed = announce_req.left == Some(0);
            }
        },
    );

    // remove expired peers (expiry + 1 minute)
    server
        .peers
        .retain(|_k, v| now < v.expire.add(Duration::seconds(60)));

    let mut peers: Vec<PeerInfo> = Vec::with_capacity(server.peers.len());
    let mut complete = 0;
    let mut incomplete = 0;
    for (k, v) in server.peers.clone() {
        if k == key {
            continue;
        }
        peers.push(v.info);
        if v.seed {
            complete += 1;
        } else {
            incomplete += 1;
        }
    }
    peers.shrink_to_fit();

    // return bencoded peer list (excluding the announcing peer)
    Ok(Response::new(
        AnnounceResponse::Success(Announce {
            warning_message: None,
            interval: std::time::Duration::from_secs(rng.gen_range(300..=310)),
            min_interval: Some(std::time::Duration::from_secs(60)),
            tracker_id: None,
            complete,
            incomplete,
            peers,
        })
        .into(),
    ))
}
