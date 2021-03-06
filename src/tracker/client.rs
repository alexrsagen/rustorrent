use super::announce::{Announce, AnnounceKey, AnnounceRequest, AnnounceResponse};
use super::udp_conn::{RequestData, ResponseData, UdpConn};

use crate::error::{Error, InvalidProto, TrackerProto};
use crate::http::{read_body, DualSchemeClient};
use crate::peer::PeerAddrAndId;
use crate::torrent::Torrent;

use hyper::http::uri::PathAndQuery;
use hyper::Uri;
use rand::Rng;
use trust_dns_resolver::TokioAsyncResolver;

use std::convert::TryInto;
use std::default::Default;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

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
    peer_self: &'a PeerAddrAndId,
    opts: TrackerClientOptions,
    http_key: AnnounceKey,
    udp_key: AnnounceKey,
}

impl<'a> TrackerClient<'a> {
    pub fn new(
        client: DualSchemeClient,
        resolver: TokioAsyncResolver,
        opts: TrackerClientOptions,
        peer_self: &'a PeerAddrAndId,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let http_key: Vec<u8> = (&mut rng)
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(20)
            .collect();
        Self {
            client,
            resolver,
            peer_self,
            opts,
            http_key: AnnounceKey::Http(http_key),
            udp_key: AnnounceKey::Udp(rng.gen()),
        }
    }

    pub fn new_with_resolver(
        resolver: TokioAsyncResolver,
        opts: TrackerClientOptions,
        peer_self: &'a PeerAddrAndId,
    ) -> Self {
        let client = DualSchemeClient::new_with_resolver(resolver.clone().into());
        Self::new(client, resolver, opts, peer_self)
    }

    fn build_announce_request(
        &self,
        torrent: &Torrent,
        tracker_id: Option<&[u8]>,
        key: AnnounceKey,
    ) -> AnnounceRequest {
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
            key: Some(key),
            tracker_id: tracker_id.map(Vec::from),
        }
    }

    fn build_announce_uri(
        &self,
        base_uri: Uri,
        torrent: &Torrent,
        tracker_id: Option<&[u8]>,
    ) -> Result<Uri, Error> {
        let query_string = self
            .build_announce_request(torrent, tracker_id, self.http_key.clone())
            .to_string();
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
                TrackerProto::Other(
                    endpoint
                        .scheme()
                        .map(|scheme| scheme.as_str().to_string())
                        .unwrap_or_default(),
                ),
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
            }
            None => {
                return Err(Error::NotConnected);
            }
        };
        // connect to tracker
        let mut conn = UdpConn::connect(addr).await?;
        // create announce request
        let req = conn.new_request(RequestData::Announce(self.build_announce_request(
            torrent,
            None,
            self.udp_key.clone(),
        )));
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
            Some("http") | Some("https") => {
                self.try_announce_http(endpoint, torrent, tracker_id).await
            }
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
