use std::{net::Ipv6Addr, process::Command};

use clap::Parser;
use ipnet::Ipv6Net;
use tun_tap::Iface;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Name of the tunnel to bring up
    #[clap(short, long)]
    pub interface: String,

    /// The network to operate with
    #[clap(short, long)]
    pub network: Ipv6Net,
}

// Casually snagged from: https://dev.to/xphoniex/ii-implementing-icmp-in-rust-3bk5
fn calculate_checksum(data: &mut [u8], source_addr: Ipv6Addr, dest_addr: Ipv6Addr, len: u16) -> [u8; 2] {

    // Build the IPv6 pseudo-header
    let mut pseudo_header = [0; 38];
    pseudo_header[0..16].copy_from_slice(&source_addr.octets());
    pseudo_header[16..32].copy_from_slice(&dest_addr.octets());
    pseudo_header[32] = 0x00;
    pseudo_header[33] = 0x20;
    pseudo_header[34] = 0x00;
    pseudo_header[35] = 0x00;
    pseudo_header[36] = 0x00;
    pseudo_header[37] = 0x3a;

    // Create our new data with the pseudo-header added
    let mut new_data = pseudo_header.to_vec();
    new_data.extend_from_slice(&data);//(&data[2..]);


    let mut f = 0;
    let mut chk: u32 = 0;
    while f + 2 <= new_data.len() {
        chk += u16::from_le_bytes(new_data[f..f + 2].try_into().unwrap()) as u32;

        f += 2;
    }

    while chk > 0xffff {
        chk = (chk & 0xffff) + (chk >> 2 * 8);
    }

    let mut chk = chk as u16;

    chk = !chk & 0xffff;

    // endianness
    chk = chk >> 8 | ((chk & 0xff) << 8);

    return [(chk >> 8) as u8, (chk & 0xff) as u8];
}

pub fn main() {
    let args = Args::parse();

    // Bring up the interface
    let tun = Iface::new(args.interface.as_str(), tun_tap::Mode::Tun).unwrap();
    println!("Brought up tun interface: {}", tun.name());

    // Calculate the gateway address
    let gateway = args.network.hosts().nth(1).unwrap();
    println!("Selected the following gateway: {}", gateway);

    // Configure the kernel for this interface
    Command::new("ip")
        .args(vec![
            "-6",
            "addr",
            "add",
            "dev",
            &tun.name(),
            format!("{}/{}", gateway.to_string(), args.network.prefix_len()).as_str(),
        ])
        .status()
        .unwrap();
    Command::new("ip")
        .args(vec!["link", "set", "up", "dev", &tun.name()])
        .status()
        .unwrap();
    print!("Kernel configuration OK");

    // Set up the packet capture
    let mut buf = [0u8; 1500];
    loop {
        let size = tun.recv(&mut buf).unwrap();
        let clean_buf = &buf[4..size];
        let size = size - 4;

        // Drop small packets
        if size < 40 {
            println!("Packet too small! Dropping.");
            continue;
        }

        // Read the TTL of the packet
        let ttl = clean_buf[7];

        // Calculate the host this request is targeting
        if let Some(targeted_host) = args.network.hosts().nth(ttl as usize) {
            // Calculate the source host addr
            let source_host = {
                let bytes = &clean_buf[8..24];
                Ipv6Addr::new(
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                    u16::from_be_bytes([bytes[4], bytes[5]]),
                    u16::from_be_bytes([bytes[6], bytes[7]]),
                    u16::from_be_bytes([bytes[8], bytes[9]]),
                    u16::from_be_bytes([bytes[10], bytes[11]]),
                    u16::from_be_bytes([bytes[12], bytes[13]]),
                    u16::from_be_bytes([bytes[14], bytes[15]]),
                )
            };

            // Print some debug info
            println!("Got: {:?}", &clean_buf);
            println!(
                "{} sent packet destined for: {}",
                source_host, targeted_host
            );

            // Build a return packet
            let mut return_packet = vec![0u8; size + 8 + 40];

            // Set the packet version (IPv6) and size
            return_packet[0] = 0x60;
            let split_size = (size + 8).to_be_bytes();
            println!("{:?}", split_size);
            return_packet[4] = split_size[6];
            return_packet[5] = split_size[7];

            // Various IP packet consts
            return_packet[6] = 0x3a;
            return_packet[7] = 0x40;

            // Set the source address as the targeted host
            return_packet[8..24].copy_from_slice(&targeted_host.octets());

            // Set the destination address as the original source address
            return_packet[24..40].copy_from_slice(&source_host.octets());

            // Set more ICMP constants
            return_packet[40] = 0x03;
            return_packet[41] = 0x00;
            return_packet[44] = 0x00;
            return_packet[45] = 0x00;
            return_packet[46] = 0x00;
            return_packet[47] = 0x00;

            // Copy the original packet into the return packet
            for i in 0..size {
                return_packet[i + 48] = clean_buf[i];
            }

            // Magic
            let checksum = calculate_checksum(&mut return_packet[8..],  targeted_host, source_host, (size + 8 )as u16);
            return_packet[42] = checksum[0];
            return_packet[43] = checksum[1];

            // Send the packet back to the tunnel
            let final_packet = vec![buf[0..4].to_vec(), return_packet].concat();
            println!("Returning: {:?}", &final_packet);
            assert!(tun.send(&final_packet).unwrap() == size + 8 + 40 + 4);
        }
    }
}
