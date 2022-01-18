use crate::peer::{PortRange};
use crate::error::{Error};

use hyper::{Body, Request, Response, Server, Method};
use hyper::service::{make_service_fn, service_fn};
use hyper::server::conn::AddrStream;

use rand::Rng;

use std::ops::RangeInclusive;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::convert::Infallible;
use std::default::Default;

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

async fn handle(
    server: TrackerHttpServer,
    addr: SocketAddr,
    req: Request<Body>
) -> Result<Response<Body>, Infallible> {
    server.handle(addr, req).await
}

#[derive(Debug, Clone)]
pub struct TrackerHttpServer {
	#[allow(unused)]
	opts: TrackerServerOptions,
	addr: SocketAddr,
}

impl TrackerHttpServer {
	pub fn new(opts: TrackerServerOptions) -> Self {
		let mut rng = rand::thread_rng();

		// get local bind address from provided port range
		let port_range: RangeInclusive<u16> = opts.port_range.into();
		let addr = SocketAddr::new(opts.ip, rng.gen_range(port_range));

		Self { opts, addr }
	}

	pub async fn run(&self) -> Result<(), Error> {
		// create and start hyper server
		let make_service = make_service_fn(move |conn: &AddrStream| {
			let server = self.clone();
			let addr = conn.remote_addr();
			let service = service_fn(move |req| {
				handle(server.clone(), addr, req)
			});
			async move { Ok::<_, Infallible>(service) }
		});
		Server::bind(&self.addr)
			.serve(make_service)
			.await
			.map_err(Error::Hyper)
	}

	async fn handle(&self, _addr: SocketAddr, req: Request<Body>) -> Result<Response<Body>, Infallible> {
		if req.uri() != "/announce" {
			return Ok(Response::builder().status(404).body(Body::empty()).unwrap());
		}
		if req.method() != Method::GET {
			return Ok(Response::builder().status(405).body(Body::empty()).unwrap());
		}
		Ok(Response::new(Body::from("Hello World")))
	}
}