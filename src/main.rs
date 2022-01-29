use structopt::StructOpt;

pub mod bencode;
pub mod bitfield;
pub mod bytesize;
pub mod cli;
pub mod http;
pub mod peer;
pub mod resolver;
pub mod skip_wrap_vec;
pub mod torrent;

pub mod tracker;
use tracker::{TrackerHttpServer, TrackerServerOptions};

pub mod error;
use error::Error;

pub mod client;
use client::{Client, ClientOptions};

use std::default::Default;
use std::sync::Arc;

pub const DEBUG: bool = true;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opt = cli::Opt::from_args();

    match opt.cmd {
        cli::Command::Download {
            torrent,
            destination,
            tracker,
        } => {
            let client = Arc::new(Client::new(ClientOptions {
                ip: opt.bind_address,
                port_range: opt.bind_port,
                download_dir: destination,
                tracker,
                ..Default::default()
            }));
            client.download(&torrent).await?;
        }
        cli::Command::Upload { .. } => {
            todo!()
        }
        cli::Command::Tracker => {
            TrackerHttpServer::run(TrackerServerOptions {
                ip: opt.bind_address,
                port_range: opt.bind_port,
            })
            .await?
        }
    }

    Ok(())
}
