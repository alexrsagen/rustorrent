use crate::tracker::announce::{Announce, AnnounceResponse};

use crate::tracker::udp_conn::{UdpConn, RequestData, ResponseData, EVENT_NONE};

use crate::http::{read_body, DualSchemeClient};
use crate::peer::PeerInfo;
use crate::error::{Error, InvalidProto, TrackerProto};
use crate::torrent::Torrent;

use trust_dns_resolver::TokioAsyncResolver;
use url::Url;
use hyper::Uri;
use rand::Rng;

use std::convert::TryInto;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::default::Default;
use std::sync::atomic::Ordering;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TrackerClientOptions {
	pub num_want: i32,
}

impl Default for TrackerClientOptions {
	fn default() -> Self {
		Self {
			num_want: 10,
		}
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
	pub fn new(client: DualSchemeClient, resolver: TokioAsyncResolver, opts: TrackerClientOptions, peer_self: &'a PeerInfo) -> Self {
		Self { client, resolver, peer_self, opts, key: rand::thread_rng().gen() }
	}

	pub fn new_with_resolver(resolver: TokioAsyncResolver, opts: TrackerClientOptions, peer_self: &'a PeerInfo) -> Self {
		let client = DualSchemeClient::new_with_resolver(resolver.clone().into());
		Self::new(client, resolver, opts, peer_self)
	}

	fn build_announce_uri(&self, mut endpoint: Url, torrent: &Torrent, tracker_id: Option<&str>) -> Result<Uri, Error> {
		let uploaded = torrent.uploaded.load(Ordering::SeqCst);
		let downloaded = torrent.downloaded.load(Ordering::SeqCst);
		endpoint.query_pairs_mut()
			.clear()
			.append_pair("info_hash", &*unsafe {String::from_utf8_unchecked(torrent.metainfo.info_hash.to_vec())})
			.append_pair("peer_id", &*unsafe {String::from_utf8_unchecked(self.peer_self.id.as_ref().unwrap().to_vec())})
			.append_pair("port", &self.peer_self.addr.port().to_string())
			.append_pair("uploaded", &uploaded.to_string())
			.append_pair("downloaded", &downloaded.to_string())
			.append_pair("compact", "1")
			.append_pair("numwant", &self.opts.num_want.to_string())
			.append_pair("left", &(torrent.metainfo.info.total_size() - downloaded).to_string());
		if let Some(tracker_id) = tracker_id {
			endpoint.query_pairs_mut()
				.append_pair("trackerid", tracker_id);
		}
		Ok(endpoint.to_string().try_into()?)
	}

	async fn try_announce_http(&self, endpoint: Url, torrent: &Torrent, tracker_id: Option<&str>) -> Result<Announce, Error> {
		let announce_uri = self.build_announce_uri(endpoint, torrent, tracker_id)?;
		let mut res = self.client.get(&announce_uri).await?;
		if crate::DEBUG {
			println!("[debug] HTTP GET {}: {}", &announce_uri, res.status());
		}
		let bytes = read_body(&mut res).await?;
		match bytes.try_into()? {
			AnnounceResponse::Failure(reason) => Err(Error::AnnounceFailed(reason)),
			AnnounceResponse::Success(announce) => Ok(announce),
		}
	}

	async fn try_announce_udp(&self, endpoint: Url, torrent: &Torrent) -> Result<Announce, Error> {
		// check scheme
		if endpoint.scheme() != "udp" {
			return Err(Error::ProtoInvalid(InvalidProto::Tracker(TrackerProto::Other(endpoint.scheme().to_owned()))));
		}
		// get port
		let port = match endpoint.port() {
			Some(port) => port,
			None => {
				return Err(Error::NotConnected);
			},
		};
		// resolve hostname
		let addr = match endpoint.host() {
			Some(host) => match host {
				url::Host::Domain(hostname) => {
					// resolve hostname to addresses
					let addrs = self.resolver.lookup_ip(hostname).await?.iter()
						.map(|ip| SocketAddr::new(ip, port))
						.collect::<Vec<SocketAddr>>();
					// range check
					if addrs.len() == 0 {
						return Err(Error::NotConnected);
					}
					// get random address from lookup result
					addrs[(&mut rand::thread_rng()).gen_range(0..addrs.len()-1)]
				},
				url::Host::Ipv4(ip) => SocketAddr::new(IpAddr::V4(ip), port),
				url::Host::Ipv6(ip) => SocketAddr::new(IpAddr::V6(ip), port),
			},
			None => {
				return Err(Error::NotConnected);
			},
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

	async fn try_announce(&self, endpoint: &str, torrent: &Torrent, tracker_id: Option<&str>) -> Result<Announce, Error> {
		let endpoint = Url::parse(endpoint)?;
		match endpoint.scheme() {
			"http" | "https" => self.try_announce_http(endpoint, torrent, tracker_id).await,
			"udp" => self.try_announce_udp(endpoint, torrent).await,
			scheme => Err(Error::ProtoInvalid(InvalidProto::Tracker(TrackerProto::Other(scheme.to_owned()))))
		}
	}

	pub async fn announce(&self, torrent: &Torrent, tracker_id: Option<&str>) -> Result<Announce, Error> {
		let mut last_error: Option<Error> = None;
		for tier_guard in torrent.announce.iter() {
			let mut tier = tier_guard.lock().await;

			// announce to endpoints in current tier, stop on first response
			let mut successful_endpoint_i: Option<usize> = None;
			let mut announce_response: Option<Announce> = None;
			for (i, endpoint) in tier.iter().enumerate() {
				match self.try_announce(endpoint, torrent, tracker_id).await {
					Ok(announce) => {
						successful_endpoint_i = Some(i);
						announce_response = Some(announce);
						break;
					},
					Err(e) => {
						last_error = Some(e);
					},
				}
			}

			// move last successful endpoint to start of tier
			if let Some(i) = successful_endpoint_i {
				let mut new_tier = Vec::with_capacity(tier.len());
				let successful_endpoint = tier.remove(i);
				new_tier.push(successful_endpoint);
				new_tier.append(&mut tier);
				*tier = new_tier;
			}

			// return if announce was successful
			if let Some(response) = announce_response {
				return Ok(response);
			}
		}
		Err(Error::AnnounceFailed(match last_error {
			Some(e) => String::from(format!("no trackers available (last error: {})", e)),
			None => String::from("no trackers available"),
		}))
	}
}