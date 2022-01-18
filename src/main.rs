use structopt::StructOpt;

pub mod bencode;
pub mod bitfield;
pub mod bytesize;
pub mod http;
pub mod resolver;
pub mod torrent;

pub mod tracker;
use tracker::{TrackerHttpServer, TrackerServerOptions};

pub mod peer;

pub mod error;
use error::Error;

use std::default::Default;

pub mod client;
use client::{Client, ClientOptions};

pub const DEBUG: bool = true;

pub mod cli;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opt = cli::Opt::from_args();

    match opt.cmd {
        cli::Command::Download {
            torrent,
            destination,
            ..
        } => {
            let client = Client::new(ClientOptions {
                ip: opt.bind_address,
                port_range: opt.bind_port,
                download_dir: destination,
                ..Default::default()
            });
            client.download(&torrent).await?;
        }
        cli::Command::Upload { .. } => {
            todo!()
        }
        cli::Command::Tracker => {
            TrackerHttpServer::new(TrackerServerOptions {
                ip: opt.bind_address,
                port_range: opt.bind_port,
            })
            .run()
            .await?
        }
    }

    Ok(())
}
