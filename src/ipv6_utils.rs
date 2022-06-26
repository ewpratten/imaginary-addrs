use std::net::Ipv6Addr;

use etherparse::Ipv6Header;
use pnet::packet::{icmpv6::Icmpv6Packet, Packet};

/// Build an IPv6 address from octets
pub fn ipv6_from_octets(octets: &[u8]) -> Ipv6Addr {
    Ipv6Addr::new(
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
        u16::from_be_bytes([octets[4], octets[5]]),
        u16::from_be_bytes([octets[6], octets[7]]),
        u16::from_be_bytes([octets[8], octets[9]]),
        u16::from_be_bytes([octets[10], octets[11]]),
        u16::from_be_bytes([octets[12], octets[13]]),
        u16::from_be_bytes([octets[14], octets[15]]),
    )
}

/// Calculate the checksum for an ICMPv6 packet
pub fn icmpv6_checksum(raw: &[u8], source: &Ipv6Addr, destination: &Ipv6Addr) -> [u8; 2] {
    // Build into a pnet-usable format
    let packet = Icmpv6Packet::new(raw).unwrap();
    println!("{:?}", packet);
    println!("{:?}", packet.payload());

    // Calculate the checksum
    let checksum = pnet::packet::icmpv6::checksum(&packet, source, destination);

    // Return the checksum in big endian format
    checksum.to_be_bytes()
}

/// Writes an IPv6 header to a buffer
pub fn ipv6_header_to_bytes(header: &Ipv6Header) -> Vec<u8> {
    let mut bytes = vec![];
    header.write(&mut bytes).unwrap();
    bytes
}
