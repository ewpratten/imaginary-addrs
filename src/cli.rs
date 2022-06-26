use clap::Parser;
use ipnet::Ipv6Net;


#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Name of the tunnel to bring up
    #[clap(short, long)]
    pub interface: String,

    /// The network to operate with
    #[clap(short, long)]
    pub network: Ipv6Net,
}