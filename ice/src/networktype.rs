// https://github.com/pion/ice/blob/f92d05f17c76e8ce326bad6cd9002f383b8d1415/networktype.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use std::net::IpAddr;

const UDP: &str = "udp";
const TCP: &str = "tcp";
const UDP4: &str = "udp4";
const UDP6: &str = "udp6";
const TCP4: &str = "tcp4";
const TCP6: &str = "tcp6";

pub(crate) fn supported_network_types() -> Vec<NetworkType> {
    vec![
        NetworkType::Udp4,
        NetworkType::Udp6,
        NetworkType::Tcp4,
        NetworkType::Tcp6,
    ]
}

/// NetworkType represents the type of network.
#[repr(u8)]
pub enum NetworkType {
    /// NetworkTypeUDP4 indicates UDP over IPv4.
    Udp4 = 1,
    /// NetworkTypeUDP6 indicates UDP over IPv6.
    Udp6 = 2,
    /// NetworkTypeTCP4 indicates TCP over IPv4.
    Tcp4 = 3,
    /// NetworkTypeTCP6 indicates TCP over IPv6.
    Tcp6 = 4,
}

impl std::fmt::Display for NetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkType::Udp4 => write!(f, "{}", UDP4),
            NetworkType::Udp6 => write!(f, "{}", UDP6),
            NetworkType::Tcp4 => write!(f, "{}", TCP4),
            NetworkType::Tcp6 => write!(f, "{}", TCP6),
        }
    }
}

impl NetworkType {
    /// IsUDP returns true when network is UDP4 or UDP6.
    pub fn is_udp(&self) -> bool {
        matches!(*self, NetworkType::Udp4 | NetworkType::Udp6)
    }

    /// IsTCP returns true when network is TCP4 or TCP6.
    pub fn is_tcp(&self) -> bool {
        matches!(*self, NetworkType::Tcp4 | NetworkType::Tcp6)
    }

    /// NetworkShort returns the short network description.
    pub fn network_short(&self) -> &str {
        match *self {
            NetworkType::Udp4 | NetworkType::Udp6 => UDP,
            NetworkType::Tcp4 | NetworkType::Tcp6 => TCP,
        }
    }

    /// IsReliable returns true if the network is reliable.
    pub fn is_reliable(&self) -> bool {
        match *self {
            NetworkType::Udp4 | NetworkType::Udp6 => false,
            NetworkType::Tcp4 | NetworkType::Tcp6 => true,
        }
    }

    /// IsIPv4 returns whether the network type is IPv4 or not.
    pub fn is_ipv4(&self) -> bool {
        matches!(*self, NetworkType::Udp4 | NetworkType::Tcp4)
    }

    // IsIPv6 returns whether the network type is IPv6 or not.
    pub fn is_ipv6(&self) -> bool {
        matches!(*self, NetworkType::Udp6 | NetworkType::Tcp6)
    }
}

/// determineNetworkType determines the type of network based on
/// the short network string and an IP address.
pub(crate) fn determine_network_type(
    network: &str,
    ip: IpAddr,
) -> Result<NetworkType, Box<dyn std::error::Error>> {
    // // we'd rather have an IPv4-mapped IPv6 become IPv4 so that it is usable.
    // ip = ip.Unmap()
    if network.to_ascii_lowercase().starts_with(UDP) {
        if ip.is_ipv4() {
            return Ok(NetworkType::Udp4);
        }

        return Ok(NetworkType::Udp6);
    }
    if network.to_ascii_lowercase().starts_with(TCP) {
        if ip.is_ipv4() {
            return Ok(NetworkType::Tcp4);
        }

        return Ok(NetworkType::Tcp6);
    }

    Err(Box::new(format!(
        "{} from {} {}",
        ErrDetermineNetworkType, network, ip
    )))
}
