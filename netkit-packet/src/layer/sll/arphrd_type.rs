//! ARPHRD (Address Resolution Protocol Hardware) types

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// ARPHRD (Address Resolution Protocol Hardware) type values.
///
/// These values identify the type of link-layer device.
/// See Linux kernel's `include/uapi/linux/if_arp.h` for the complete list.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    FromPrimitive,
    IntoPrimitive,
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u16)]
#[non_exhaustive]
pub enum ArphrdType {
    /// NET/ROM pseudo
    Netrom = 0,
    /// Ethernet 10/100Mbps
    Ether = 1,
    /// Experimental Ethernet
    Eether = 2,
    /// AX.25 Level 2
    Ax25 = 3,
    /// PROnet token ring
    Pronet = 4,
    /// Chaosnet
    Chaos = 5,
    /// IEEE 802.2 Ethernet/TR/TB
    Ieee802 = 6,
    /// ARCnet
    Arcnet = 7,
    /// APPLEtalk
    Appletalk = 8,
    /// Frame Relay DLCI
    Dlci = 15,
    /// ATM
    Atm = 19,
    /// Metricom STRIP (new IANA id)
    Metricom = 23,
    /// IEEE 1394 IPv4 - RFC 2734
    Ieee1394 = 24,
    /// EUI-64
    Eui64 = 27,
    /// InfiniBand
    Infiniband = 32,
    /// SLIP
    Slip = 256,
    /// CSLIP
    Cslip = 257,
    /// SLIP6
    Slip6 = 258,
    /// CSLIP6
    Cslip6 = 259,
    /// Notional KISS type
    Rsrvd = 260,
    /// ADAPT
    Adapt = 264,
    /// ROSE
    Rose = 270,
    /// CCITT X.25
    X25 = 271,
    /// Boards with X.25 in firmware
    Hwx25 = 272,
    /// Controller Area Network (CAN)
    Can = 280,
    /// PPP
    Ppp = 512,
    /// Cisco HDLC
    Hdlc = 513,
    /// LAPB
    Lapb = 516,
    /// Digital's DDCMP protocol
    Ddcmp = 517,
    /// Raw HDLC
    Rawhdlc = 518,
    /// Raw IP
    Rawip = 519,
    /// IPIP tunnel
    Tunnel = 768,
    /// IP over DDP tunneller
    Tunnel6 = 769,
    /// Frame Relay Access Device
    Frad = 770,
    /// SKIP vif
    Skip = 771,
    /// Loopback device
    Loopback = 772,
    /// Localtalk device
    Localtalk = 773,
    /// Fiber Distributed Data Interface
    Fddi = 774,
    /// AP1000 BIF
    Bif = 775,
    /// sit0 device - IPv6-in-IPv4
    Sit = 776,
    /// IP over DDP tunneller
    Ipddp = 777,
    /// GRE over IP
    Ipgre = 778,
    /// PIMSM register interface
    Pimreg = 779,
    /// High Performance Parallel Interface
    Hippi = 780,
    /// Nexus 64Mbps Ash
    Ash = 781,
    /// Acorn Econet
    Econet = 782,
    /// Linux-IrDA
    Irda = 783,
    /// Point to point fibrechannel
    Fcpp = 784,
    /// Fibrechannel arbitrated loop
    Fcal = 785,
    /// Fibrechannel public loop
    Fcpl = 786,
    /// Fibrechannel fabric
    Fcfabric = 787,
    /// Magic type ident for TR
    Ieee802Tr = 800,
    /// IEEE 802.11
    Ieee80211 = 801,
    /// IEEE 802.11 + Prism2 header
    Ieee80211Prism = 802,
    /// IEEE 802.11 + radiotap header
    Ieee80211Radiotap = 803,
    /// IEEE 802.15.4
    Ieee802154 = 804,
    /// IEEE 802.15.4 network monitor
    Ieee802154Monitor = 805,
    /// PhoNet media type
    Phonet = 820,
    /// PhoNet pipe header
    PhonetPipe = 821,
    /// CAIF media type
    Caif = 822,
    /// GRE over IPv6
    Ip6gre = 823,
    /// Netlink header
    Netlink = 824,
    /// IPv6 over LoWPAN
    SixLowpan = 825,
    /// Vsock monitor header
    VsockMon = 826,

    /// Unknown ARPHRD type
    #[num_enum(catch_all)]
    Unknown(u16),
}

#[allow(clippy::derivable_impls)]
impl Default for ArphrdType {
    fn default() -> Self {
        ArphrdType::Ether
    }
}

impl_target!(frominto, ArphrdType, u16);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{test_enum_num, test_enum_str};

    use super::*;

    #[test]
    fn arphrd_type_str() {
        test_enum_str!(
            ArphrdType,
            Ether => "Ether",
            Loopback => "Loopback",
            Can => "Can",
            Ieee802 => "Ieee802",
            Ppp => "Ppp",
        );
    }

    #[test]
    fn arphrd_type_num() {
        test_enum_num!(
            ArphrdType: u16,
            Ether => 1,
            Loopback => 772,
            Can => 280,
            Ieee802 => 6,
            Ppp => 512,
        );
    }

    #[test]
    fn arphrd_type_default() {
        assert_eq!(ArphrdType::default(), ArphrdType::Ether);
    }

    #[test]
    fn arphrd_type_unknown() {
        let unknown: ArphrdType = 9999u16.into();
        assert!(matches!(unknown, ArphrdType::Unknown(9999)));
    }
}
