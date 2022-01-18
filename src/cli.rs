use std::{net::IpAddr, path::PathBuf};

use structopt::StructOpt;

use crate::peer::PortRange;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "rusttorrent",
    about = "BitTorrent research client built in rust"
)]
pub struct Opt {
    /// IP address to bind to
    #[structopt(short = "b", long = "bind-address", default_value = "::")]
    pub bind_address: IpAddr,

    /// Port (range) to bind to
    #[structopt(short = "p", long = "bind-port", default_value = "1024-65535")]
    pub bind_port: PortRange,

    /// Action to perform
    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    /// Downloads/leeches a torrent
    Download {
        /// Torrent file path or URL
        torrent: String,

        /// Download directory
        #[structopt(default_value = ".")]
        destination: PathBuf,

        /// Optional tracker URL
        tracker: Option<String>,
    },

    /// Uploads/seeds a torrent
    Upload {
        /// Torrent file path or URL
        torrent: String,

        /// Donwload directory
        #[structopt(default_value = ".")]
        destination: PathBuf,
    },

    /// Starts a tracker
    Tracker,
}
