//! Ethernet Type

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// Ethernet Type
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(
    // core traits
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    // num_enum traits
    FromPrimitive,
    IntoPrimitive,
    // strum traits
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u16)]
#[non_exhaustive]
pub enum EthType {
    /// Internet Protocol version 4 (IPv4)
    Ipv4 = 0x0800,

    /// Address Resolution Protocol (ARP)
    Arp = 0x0806,

    /// Frame Relay ARP
    FrameRelayArp = 0x0808,

    /// Customer VLAN Tag Type
    Vlan = 0x8100,

    /// Internet Protocol version 6 (IPv6)
    Ipv6 = 0x86DD,

    /// Represents any other EthType
    #[num_enum(catch_all)]
    Reserved(u16),
}

impl Default for EthType {
    fn default() -> Self {
        EthType::Reserved(0xFFFF)
    }
}

impl_target!(frominto, EthType, u16);
