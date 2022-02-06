use crate::error::{Error};
use super::DualSchemeClient;

use hyper::Uri;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const EXTERNAL_IP_ENDPOINTS: [&'static str; 4] = [
    "https://ip.kitcloud.no/raw",
    "https://icanhazip.com",
    "https://api64.ipify.org",
    "https://ident.me",
];

const EXTERNAL_IPV4_ENDPOINTS: [&'static str; 4] = [
    "https://ipv4.kitcloud.no/raw",
    "https://ipv4.icanhazip.com",
    "https://api.ipify.org",
    "http://ipv4.ident.me",
];

const EXTERNAL_IPV6_ENDPOINTS: [&'static str; 4] = [
    "https://ipv6.kitcloud.no/raw",
    "https://ipv6.icanhazip.com",
    "https://api6.ipify.org",
    "http://ipv6.ident.me",
];

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DualStackIpAddr {
	V4(Ipv4Addr),
	V6(Ipv6Addr),
	Both { v4: Ipv4Addr, v6: Ipv6Addr },
}

async fn lookup_parse_ip(client: DualSchemeClient, endpoints: &[&'static str]) -> Result<IpAddr, Error> {
	let mut last_error: Option<Error> = None;
	for endpoint in endpoints {
		match client.get_string(&Uri::from_static(endpoint)).await {
			Ok(bodystr) => match bodystr.parse::<IpAddr>() {
				Ok(ip) => return Ok(ip),
				Err(e) => {
					last_error = Some(e.into());
					continue;
				}
			},
			Err(e) => last_error = Some(e),
		}
	}
	Err(Error::PublicIpLookupFailed(match last_error {
		Some(e) => format!("no endpoints available (last error: {})", e),
		None => String::from("no endpoints available"),
	}))
}

pub async fn lookup_ip(client: DualSchemeClient) -> Result<IpAddr, Error> {
	lookup_parse_ip(client, &EXTERNAL_IP_ENDPOINTS).await
}

pub async fn lookup_ipv4(client: DualSchemeClient) -> Result<Ipv4Addr, Error> {
	let ip = lookup_parse_ip(client, &EXTERNAL_IPV4_ENDPOINTS).await?;
	if let IpAddr::V4(ipv4) = ip {
		return Ok(ipv4);
	}
	Err(Error::PublicIpLookupFailed("no IPv4 address in response".into()))
}

pub async fn lookup_ipv6(client: DualSchemeClient) -> Result<Ipv6Addr, Error> {
	let ip = lookup_parse_ip(client, &EXTERNAL_IPV6_ENDPOINTS).await?;
	if let IpAddr::V6(ipv6) = ip {
		return Ok(ipv6);
	}
	Err(Error::PublicIpLookupFailed("no IPv6 address in response".into()))
}

pub async fn lookup_dualstack_ip(client: DualSchemeClient) -> Result<DualStackIpAddr, Error> {
	let (v4, v6) = futures_util::future::join(
		lookup_ipv4(client.clone()),
		lookup_ipv6(client)
	).await;
	if let Ok(v4) = v4 {
		if let Ok(v6) = v6 {
			Ok(DualStackIpAddr::Both{v4, v6})
		} else {
			Ok(DualStackIpAddr::V4(v4))
		}
	} else if let Ok(v6) = v6 {
		Ok(DualStackIpAddr::V6(v6))
	} else if let Err(e) = v4 {
		Err(e)
	} else {
		Err(Error::PublicIpLookupFailed("no public IP found".into()))
	}
}