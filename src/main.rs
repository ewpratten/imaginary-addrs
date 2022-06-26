use std::{net::Ipv6Addr, process::Command, vec};

use clap::Parser;
use ipnet::Ipv6Net;
use tun_tap::Iface;

mod cli;
mod ipv6_utils;

use cli::Args;
use ipv6_utils::ipv6_from_octets;

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
        .args(vec!["link", "set", "up", "dev", &tun.name()])
        .status()
        .unwrap();
    Command::new("ip")
        .args(vec![
            "-6",
            "addr",
            "add",
            &gateway.to_string(),
            "dev",
            &tun.name(),
        ])
        .status()
        .unwrap();
    Command::new("ip")
        .args(vec![
            "-6",
            "route",
            "add",
            format!("{}/{}", gateway.to_string(), args.network.prefix_len()).as_str(),
            "dev",
            &tun.name(),
        ])
        .status()
        .unwrap();
    Command::new("sysctl")
        .args(vec!["-w", "net.ipv6.conf.all.forwarding=1"])
        .status()
        .unwrap();
    println!("Kernel configuration OK");

    // Set up the packet capture
    let mut buf = [0u8; 1500];
    loop {
        let size = tun.recv(&mut buf).unwrap();
        let packet_prefix = &buf[..4];

        // Read the packet into a reasonably parsable form
        if let Ok(inbound_ip_packet) = etherparse::PacketHeaders::from_ip_slice(&buf[4..size]) {
            // Ensure this is an IPv6 packet
            if let Some(etherparse::IpHeader::Version6(inbound_ip_header, inbound_ip_extensions)) =
                inbound_ip_packet.ip
            {
                // // Only handle ICMPv6 packets
                // if inbound_ip_header.next_header == 0x3a {
                // Ensure the requested host is in the network
                if let Some(targeted_host) = args
                    .network
                    .hosts()
                    .nth(inbound_ip_header.hop_limit as usize)
                {
                    // Parse the source and dest addresses
                    let inbound_source_addr = ipv6_from_octets(&inbound_ip_header.source);
                    let inbound_dest_addr = ipv6_from_octets(&inbound_ip_header.destination);
                    println!(
                        "Got ICMPv6 packet from {} destined for {}",
                        inbound_source_addr, inbound_dest_addr
                    );

                    // Construct a return packet header
                    let outbound_ip_header = etherparse::Ipv6Header {
                        traffic_class: 0x00,
                        flow_label: 0x00,
                        // The payload of our return packet will include 8 control bytes, and a clone of the original packet's payload
                        payload_length: size as u16 - 4 + 8,
                        next_header: 0x3a,
                        hop_limit: 0x40,
                        source: targeted_host.octets(),
                        destination: inbound_source_addr.octets(),
                    };
                    let outbound_ip_header_bytes =
                        ipv6_utils::ipv6_header_to_bytes(&outbound_ip_header);
                    println!(
                        "{:?} {}",
                        outbound_ip_header_bytes,
                        outbound_ip_header_bytes.len()
                    );

                    // Build a vec to store our outbound packet in
                    let mut outbound_bytes =
                        vec![0u8; outbound_ip_header_bytes.len() + size as usize - 4 + 8];

                    // Write our header to the vec
                    outbound_bytes[..outbound_ip_header_bytes.len()]
                        .copy_from_slice(&outbound_ip_header_bytes);

                    // Write our control bytes to the vec
                    outbound_bytes[outbound_ip_header_bytes.len()] = 0x03;
                    // The next 7 bytes are zeros

                    // Copy the original packet's payload to the vec
                    outbound_bytes[outbound_ip_header_bytes.len() + 8..]
                        .copy_from_slice(&buf[4..size]);

                    // Calculate the checksum for the packet
                    let check = ipv6_utils::icmpv6_checksum(
                        &outbound_bytes[outbound_ip_header_bytes.len()..],
                        &targeted_host,
                        &inbound_source_addr,
                    );

                    // Write the checksum to the vec
                    outbound_bytes[outbound_ip_header.header_len() + 2] = check[0];
                    outbound_bytes[outbound_ip_header.header_len() + 3] = check[1];
                    println!("{:?}", outbound_bytes);

                    // Send the packet back to the client
                    tun.send(&[packet_prefix, outbound_bytes.as_slice()].concat())
                        .unwrap();
                }
                // }
            }
        }
    }
}
