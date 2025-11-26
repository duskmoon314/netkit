//! Link-layer header type definitions.
//!
//! These correspond to the LINKTYPE values used in pcap and pcapng files.
//! See <https://www.tcpdump.org/linktypes.html> for the official registry.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::error::CaptureError;

/// Link-layer header type for captured packets.
///
/// This enum represents the type of link-layer header present in captured
/// packets. The values correspond to the LINKTYPE registry maintained by
/// tcpdump.org.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    IntoPrimitive,
    FromPrimitive,
    EnumString,
    Display,
    AsRefStr,
)]
#[repr(u32)]
pub enum LinkType {
    /// BSD loopback encapsulation (LINKTYPE_NULL)
    #[strum(serialize = "NULL")]
    Null = 0,

    /// IEEE 802.3 Ethernet (LINKTYPE_ETHERNET)
    #[strum(serialize = "Ethernet", serialize = "EN10MB")]
    Ethernet = 1,

    /// Experimental Ethernet (3Mb) (LINKTYPE_EXP_ETHERNET)
    #[strum(serialize = "EN3MB")]
    ExpEthernet = 2,

    /// AX.25 packet (LINKTYPE_AX25)
    #[strum(serialize = "AX25")]
    Ax25 = 3,

    /// IEEE 802.5 Token Ring (LINKTYPE_TOKEN_RING)
    #[strum(serialize = "IEEE802")]
    TokenRing = 6,

    /// ARCNET Data Packets (LINKTYPE_ARCNET)
    #[strum(serialize = "ARCNET_BSD")]
    Arcnet = 7,

    /// SLIP (LINKTYPE_SLIP)
    #[strum(serialize = "SLIP")]
    Slip = 8,

    /// PPP (LINKTYPE_PPP)
    #[strum(serialize = "PPP")]
    Ppp = 9,

    /// FDDI (LINKTYPE_FDDI)
    #[strum(serialize = "FDDI")]
    Fddi = 10,

    /// Raw IP packets (LINKTYPE_RAW)
    #[strum(serialize = "RAW")]
    Raw = 101,

    /// IEEE 802.11 wireless LAN (LINKTYPE_IEEE802_11)
    #[strum(serialize = "IEEE802_11")]
    Ieee80211 = 105,

    /// Linux cooked capture v1 (LINKTYPE_LINUX_SLL)
    #[strum(serialize = "LINUX_SLL")]
    LinuxSll = 113,

    /// Prism monitor mode (LINKTYPE_PRISM_HEADER)
    #[strum(serialize = "PRISM_HEADER")]
    PrismHeader = 119,

    /// Aironet header (LINKTYPE_AIRONET_HEADER)
    #[strum(serialize = "AIRONET_HEADER")]
    AironetHeader = 120,

    /// Radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)
    #[strum(serialize = "IEEE802_11_RADIOTAP")]
    Ieee80211Radiotap = 127,

    /// IPv4 packets with no link-layer header (LINKTYPE_IPV4)
    #[strum(serialize = "IPV4")]
    Ipv4 = 228,

    /// IPv6 packets with no link-layer header (LINKTYPE_IPV6)
    #[strum(serialize = "IPV6")]
    Ipv6 = 229,

    /// Linux cooked capture v2 (LINKTYPE_LINUX_SLL2)
    #[strum(serialize = "LINUX_SLL2")]
    LinuxSll2 = 276,

    /// Unknown or unsupported link type with raw value.
    #[num_enum(catch_all)]
    Unknown(u32),
}

// num_enum's catch_all does not work with derive(Default)
#[allow(clippy::derivable_impls)]
impl Default for LinkType {
    fn default() -> Self {
        LinkType::Ethernet
    }
}

impl LinkType {
    /// Get the numeric value of this link type.
    #[inline]
    pub fn as_u32(&self) -> u32 {
        u32::from(*self)
    }

    /// Check if this is a known link type.
    #[inline]
    pub fn is_known(&self) -> bool {
        !matches!(self, LinkType::Unknown(_))
    }

    /// Try to convert a u32 to a known LinkType.
    ///
    /// Returns an error for unknown link types instead of `LinkType::Unknown`.
    pub fn try_from_u32(value: u32) -> Result<Self, CaptureError> {
        let lt = LinkType::from(value);
        if lt.is_known() {
            Ok(lt)
        } else {
            Err(CaptureError::UnsupportedLinkType(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_linktype_from_u32() {
        assert_eq!(LinkType::from(1u32), LinkType::Ethernet);
        assert_eq!(LinkType::from(101u32), LinkType::Raw);
        assert_eq!(LinkType::from(9999u32), LinkType::Unknown(9999));
    }

    #[test]
    fn test_linktype_to_u32() {
        assert_eq!(LinkType::Ethernet.as_u32(), 1);
        assert_eq!(LinkType::Raw.as_u32(), 101);
        assert_eq!(LinkType::Unknown(9999).as_u32(), 9999);
    }

    #[test]
    fn test_linktype_try_from_u32() {
        assert!(LinkType::try_from_u32(1).is_ok());
        assert!(LinkType::try_from_u32(9999).is_err());
    }

    #[test]
    fn test_linktype_display() {
        // Display uses first serialize value or variant name
        assert_eq!(format!("{}", LinkType::Ethernet), "Ethernet");
        assert_eq!(format!("{}", LinkType::Raw), "RAW");
        assert_eq!(format!("{}", LinkType::Null), "NULL");
    }

    #[test]
    fn test_linktype_from_str() {
        // Can parse from any serialize alias
        assert_eq!(LinkType::from_str("EN10MB").unwrap(), LinkType::Ethernet);
        assert_eq!(LinkType::from_str("Ethernet").unwrap(), LinkType::Ethernet);
        assert_eq!(LinkType::from_str("RAW").unwrap(), LinkType::Raw);
        assert_eq!(LinkType::from_str("NULL").unwrap(), LinkType::Null);
    }

    #[test]
    fn test_linktype_is_known() {
        assert!(LinkType::Ethernet.is_known());
        assert!(!LinkType::Unknown(9999).is_known());
    }

    #[test]
    fn test_linktype_as_ref_str() {
        // AsRefStr uses first serialize value or variant name
        assert_eq!(LinkType::Ethernet.as_ref(), "Ethernet");
        assert_eq!(LinkType::Raw.as_ref(), "RAW");
        assert_eq!(LinkType::Null.as_ref(), "NULL");
    }
}
