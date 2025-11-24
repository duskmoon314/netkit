#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LinkType {
    /// BSD loopback encapsulation
    Null = 0,
    /// IEEE 802.3 Ethernet
    Ethernet = 1,
    /// Experimental Ethernet (3Mb)
    ExpEthernet = 2,
    /// AX.25 packet
    Ax25 = 3,
    /// IEEE 802.5 Token Ring
    TokenRing = 6,
    /// ARCNET Data Packets
    Arcnet = 7,
    /// SLIP
    Slip = 8,
    /// PPP
    Ppp = 9,
    /// FDDI
    Fddi = 10,
    /// Raw IP packets (no link layer header)
    Raw = 101,
    /// IEEE 802.11 wireless LAN
    Ieee80211 = 105,
    /// Linux cooked capture v1
    LinuxSll = 113,
    /// Prism monitor mode
    PrismHeader = 119,
    /// Aironet header
    AironetHeader = 120,
    /// Radiotap header
    Ieee80211Radiotap = 127,
    /// Linux cooked capture v2
    LinuxSll2 = 276,
    /// IPv4 packets with no link-layer header
    Ipv4 = 228,
    /// IPv6 packets with no link-layer header
    Ipv6 = 229,
}

impl From<u32> for LinkType {
    fn from(value: u32) -> Self {
        match value {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            2 => LinkType::ExpEthernet,
            3 => LinkType::Ax25,
            6 => LinkType::TokenRing,
            7 => LinkType::Arcnet,
            8 => LinkType::Slip,
            9 => LinkType::Ppp,
            10 => LinkType::Fddi,
            101 => LinkType::Raw,
            105 => LinkType::Ieee80211,
            113 => LinkType::LinuxSll,
            119 => LinkType::PrismHeader,
            120 => LinkType::AironetHeader,
            127 => LinkType::Ieee80211Radiotap,
            228 => LinkType::Ipv4,
            229 => LinkType::Ipv6,
            276 => LinkType::LinuxSll2,
            _ => todo!("unsupported link type: {}", value),
        }
    }
}
