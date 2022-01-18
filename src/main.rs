extern crate nom;
extern crate sha1;
extern crate hex;
extern crate bytes;
extern crate tokio_util;
extern crate hostname;
extern crate rustls;
extern crate webpki_roots;
extern crate hyper;
extern crate hyper_rustls;
extern crate trust_dns_resolver;
extern crate async_compression;
extern crate futures_core;
extern crate futures_util;
extern crate crossbeam_queue;
extern crate crossbeam_utils;
extern crate tokio;
extern crate rand;
extern crate chrono;

extern crate url;
use url::Url;

extern crate clap;
use clap::{Arg, App, AppSettings, SubCommand};

pub mod resolver;
pub mod http;
pub mod bencode;
pub mod bitfield;
pub mod bytesize;
pub mod torrent;

pub mod tracker;
use tracker::{TrackerHttpServer, TrackerServerOptions};

pub mod peer;
use peer::PortRange;

pub mod error;
use error::Error;

use std::net::IpAddr;
use std::path::PathBuf;
use std::default::Default;

pub mod client;
use client::{Client, ClientOptions};

pub const DEBUG: bool = true;

#[tokio::main]
async fn main() -> Result<(), Error> {
	let matches = App::new("rustorrent")
		.version("1.0.0")
		.author("Alexander Sagen <alexander@sagen.me>")
		.about("BitTorrent research client built in Rust")
		.arg(Arg::with_name("bind-address")
			.short("b")
			.takes_value(true)
			.default_value("::")
			.validator(validate_ipaddr)
			.help("IP address to bind to"))
		.arg(Arg::with_name("bind-port")
			.short("p")
			.takes_value(true)
			.default_value("1024-65535")
			.validator(validate_portrange)
			.help("Port (range) to bind to"))
		.setting(AppSettings::SubcommandRequired)
		.subcommand(SubCommand::with_name("upload")
			.alias("seed")
			.about("Uploads/seeds a torrent")
			.arg(Arg::with_name("torrent")
				.required(true)
				.takes_value(true)
				.validator(validate_path_or_url)
				.index(1)
				.help("Torrent file path"))
			.arg(Arg::with_name("download-dir")
				.takes_value(true)
				.validator(validate_path)
				.default_value(".")
				.index(2)
				.help("Download directory")))
		.subcommand(SubCommand::with_name("download")
			.alias("leech")
			.about("Downloads/leeches a torrent")
			.arg(Arg::with_name("torrent")
				.required(true)
				.takes_value(true)
				.validator(validate_path_or_url)
				.index(1)
				.help("Torrent file path"))
			.arg(Arg::with_name("download-dir")
				.takes_value(true)
				.validator(validate_path)
				.default_value(".")
				.index(2)
				.help("Download directory"))
			.arg(Arg::with_name("tracker")
				.takes_value(true)
				.validator(validate_url)
				.help("Override tracker announce URL (optional)")))
		.subcommand(SubCommand::with_name("tracker")
			.about("Starts a minimal torrent tracker"))
		.get_matches();

	let ip = matches.value_of("bind-address").unwrap_or("::").parse::<IpAddr>().unwrap();
	let port_range = matches.value_of("bind-port").unwrap_or("1024-65535").parse::<PortRange>().unwrap();
	let download_dir = matches.value_of("download-dir").unwrap_or(".").parse::<PathBuf>().unwrap();

	match matches.subcommand() {
		("download", Some(sub_m)) => {
			let client = Client::new(ClientOptions { ip, port_range, download_dir, ..Default::default() });
			client.download(sub_m.value_of("torrent").unwrap()).await
		},
		("upload", Some(sub_m)) => {
			eprintln!("Not implemented yet");
			Ok(())
		},
		("tracker", Some(sub_m)) => {
			TrackerHttpServer::new(TrackerServerOptions { ip, port_range }).run().await
		},
		_ => Err(Error::InvalidCommand),
	}
}

fn validate_ipaddr(input: String) -> Result<(), String> {
	match input.parse::<IpAddr>() {
		Ok(_) => Ok(()),
		Err(e) => Err(e.to_string())
	}
}

fn validate_portrange(input: String) -> Result<(), String> {
	match input.parse::<PortRange>() {
		Ok(_) => Ok(()),
		Err(e) => Err(e.to_string())
	}
}

fn validate_path(input: String) -> Result<(), String> {
	match input.parse::<PathBuf>() {
		Ok(_) => Ok(()),
		Err(e) => Err(e.to_string())
	}
}

fn validate_url(input: String) -> Result<(), String> {
	match input.parse::<Url>() {
		Ok(_) => Ok(()),
		Err(e) => Err(e.to_string())
	}
}

fn validate_path_or_url(input: String) -> Result<(), String> {
	validate_path(input.clone()).or(validate_url(input))
}