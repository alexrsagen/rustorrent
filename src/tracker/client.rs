use crate::tracker::announce::{Announce, AnnounceResponse};
use crate::tracker::udp_conn::{RequestData, ResponseData, UdpConn, EVENT_NONE};

use crate::error::{Error, InvalidProto, TrackerProto};
use crate::http::{read_body, DualSchemeClient};
use crate::peer::PeerInfo;
use crate::torrent::Torrent;

use hyper::Uri;
use hyper::http::uri::PathAndQuery;
use rand::Rng;
use trust_dns_resolver::TokioAsyncResolver;

use std::convert::TryInto;
use std::default::Default;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;

use super::announce::AnnounceRequest;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TrackerClientOptions {
    pub num_want: i32,
}

impl Default for TrackerClientOptions {
    fn default() -> Self {
        Self { num_want: 10 }
    }
}

pub struct TrackerClient<'a> {
    client: DualSchemeClient,
    resolver: TokioAsyncResolver,
    peer_self: &'a PeerInfo,
    opts: TrackerClientOptions,
    key: u32,
}

impl<'a> TrackerClient<'a> {
    pub fn new(
        client: DualSchemeClient,
        resolver: TokioAsyncResolver,
        opts: TrackerClientOptions,
        peer_self: &'a PeerInfo,
    ) -> Self {
        Self {
            client,
            resolver,
            peer_self,
            opts,
            key: rand::thread_rng().gen(),
        }
    }

    pub fn new_with_resolver(
        resolver: TokioAsyncResolver,
        opts: TrackerClientOptions,
        peer_self: &'a PeerInfo,
    ) -> Self {
        let client = DualSchemeClient::new_with_resolver(resolver.clone().into());
        Self::new(client, resolver, opts, peer_self)
    }

    fn build_announce_request(&self, torrent: &Torrent, tracker_id: Option<&[u8]>) -> AnnounceRequest {
        let uploaded = torrent.uploaded.load(Ordering::SeqCst);
        let downloaded = torrent.downloaded.load(Ordering::SeqCst);

        AnnounceRequest {
            info_hash: Some(torrent.metainfo.info_hash),
            peer_id: self.peer_self.id,
            port: Some(self.peer_self.addr.port()),
            uploaded: Some(uploaded),
            downloaded: Some(downloaded),
            left: Some(torrent.metainfo.info.total_size() - downloaded),
            compact: true,
            no_peer_id: false,
            event: None,
            ip: None,
            num_want: Some(self.opts.num_want),
            key: None,
            tracker_id: tracker_id.map(Vec::from),
        }
    }

    fn build_announce_uri(
        &self,
        base_uri: Uri,
        torrent: &Torrent,
        tracker_id: Option<&[u8]>,
    ) -> Result<Uri, Error> {
        let query_string = self.build_announce_request(torrent, tracker_id).to_string();
        if base_uri.scheme().is_none() || base_uri.authority().is_none() {
            return Err(Error::NotConnected);
        }
        let mut path_and_query = base_uri.path().to_string();
        path_and_query.push_str("?");
        path_and_query.push_str(&query_string);
        Uri::builder()
            .scheme(base_uri.scheme().unwrap().clone())
            .authority(base_uri.authority().unwrap().clone())
            .path_and_query(PathAndQuery::try_from(path_and_query)?)
            .build()
            .map_err(Error::from)
    }

    async fn try_announce_http(
        &self,
        base_uri: Uri,
        torrent: &Torrent,
        tracker_id: Option<&[u8]>,
    ) -> Result<Announce, Error> {
        let announce_uri = self.build_announce_uri(base_uri, torrent, tracker_id)?;
        if crate::DEBUG {
            println!("[debug] HTTP GET {}", &announce_uri);
        }
        let mut res = self.client.get(&announce_uri).await?;
        if crate::DEBUG {
            println!("[debug] {:?} {}", res.version(), res.status());
        }
        let bytes = read_body(&mut res).await?;
        match bytes.try_into()? {
            AnnounceResponse::Failure(reason) => Err(Error::AnnounceFailed(reason)),
            AnnounceResponse::Success(announce) => Ok(announce),
        }
    }

    async fn try_announce_udp(&self, endpoint: Uri, torrent: &Torrent) -> Result<Announce, Error> {
        // check scheme
        if endpoint.scheme().map(|scheme| scheme.as_str()) != Some("udp") {
            return Err(Error::ProtoInvalid(InvalidProto::Tracker(
                TrackerProto::Other(endpoint.scheme().map(|scheme| scheme.as_str().to_string()).unwrap_or_default()),
            )));
        }
        // get port
        let port = match endpoint.port() {
            Some(port) => port.as_u16(),
            None => {
                return Err(Error::NotConnected);
            }
        };
        // resolve hostname
        let addr = match endpoint.host() {
            Some(host) => {
                // resolve hostname to addresses
                let addrs = self
                    .resolver
                    .lookup_ip(host)
                    .await?
                    .iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect::<Vec<SocketAddr>>();
                // range check
                if addrs.is_empty() {
                    return Err(Error::NotConnected);
                }
                // get random address from lookup result
                addrs[(&mut rand::thread_rng()).gen_range(0..addrs.len() - 1)]
            },
            None => {
                return Err(Error::NotConnected);
            }
        };
        // connect to tracker
        let mut conn = UdpConn::connect(addr).await?;
        // create announce request
        let downloaded = torrent.downloaded.load(Ordering::SeqCst);
        let uploaded = torrent.uploaded.load(Ordering::SeqCst);
        let req = conn.new_request(RequestData::Announce {
            info_hash: torrent.metainfo.info_hash,
            peer_id: self.peer_self.id.as_ref().unwrap().to_owned(),
            downloaded: downloaded as i64,
            left: (torrent.metainfo.info.total_size() - downloaded) as i64,
            uploaded: uploaded as i64,
            event: EVENT_NONE,
            ip_addr: Ipv4Addr::new(0, 0, 0, 0), // use whatever IP address we connect from
            key: self.key,
            num_want: 10,
            port,
            auth: None,
            request_string: Some(endpoint.path().to_owned()),
        });
        let res = conn.perform_req(&req).await?;
        match res.data {
            ResponseData::Announce(announce) => Ok(announce),
            ResponseData::Error { error } => Err(Error::TrackerError(error)),
            _ => Err(Error::MessageInvalid),
        }
    }

    async fn try_announce(
        &self,
        endpoint: &str,
        torrent: &Torrent,
        tracker_id: Option<&[u8]>,
    ) -> Result<Announce, Error> {
        let endpoint = Uri::try_from(endpoint)?;
        match endpoint.scheme().map(|scheme| scheme.as_str()) {
            Some("http") | Some("https") => self.try_announce_http(endpoint, torrent, tracker_id).await,
            Some("udp") => self.try_announce_udp(endpoint, torrent).await,
            scheme => Err(Error::ProtoInvalid(InvalidProto::Tracker(
                TrackerProto::Other(scheme.map(str::to_string).unwrap_or_default()),
            ))),
        }
    }

    pub async fn announce(
        &self,
        torrent: &Torrent,
        tracker_id: Option<&[u8]>,
    ) -> Result<Announce, Error> {
        let mut last_error: Option<Error> = None;
        for tier in &torrent.announce {
            // announce to endpoints in current tier, stop on first response
            let mut successful_endpoint_i: Option<usize> = None;
            let mut announce_response: Option<Announce> = None;
            for (i, endpoint) in tier.into_iter().enumerate() {
                match self.try_announce(endpoint, torrent, tracker_id).await {
                    Ok(announce) => {
                        successful_endpoint_i = Some(i);
                        announce_response = Some(announce);
                        break;
                    }
                    Err(e) => {
                        last_error = Some(e);
                    }
                }
            }

            // move last successful endpoint to start of tier
            if let Some(i) = successful_endpoint_i {
                tier.set_first_item(i);
            }

            // return if announce was successful
            if let Some(response) = announce_response {
                return Ok(response);
            }
        }
        Err(Error::AnnounceFailed(match last_error {
            Some(e) => format!("no trackers available (last error: {})", e),
            None => String::from("no trackers available"),
        }))
    }
}
