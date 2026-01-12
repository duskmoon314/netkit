//! The implementation of various network layers.

pub mod dns;
pub mod eth;
pub mod icmp;
pub mod ip;
pub mod sll;
pub mod tcp;
pub mod udp;
pub mod vlan;

/// prelude module for layer.
pub mod prelude {
    pub use super::eth::{Eth, EthAddr, EthAddrError, EthError, EthType};

    pub use super::vlan::{Vlan, VlanError};

    pub use super::ip::{IpProtocol, Ipv4, Ipv4Error, Ipv6, Ipv6Error};

    pub use super::icmp::{
        Icmpv4, Icmpv4EchoBuilder, Icmpv4Error, Icmpv4Type,
        Icmpv6, Icmpv6Error, Icmpv6Type,
        IcmpEcho, IcmpDestUnreach,
        DestUnreachCode, RedirectCode, TimeExceededCode,
    };

    pub use super::udp::{Udp, UdpError};

    pub use super::tcp::{Tcp, TcpError};

    pub use super::dns::{
        Dns, DnsClass, DnsError, DnsLabel, DnsName, DnsNameError, DnsOpCode, DnsQuestion, DnsRCode,
        DnsResourceRecord, DnsRrType,
    };

    pub use super::sll::{ArphrdType, PacketType, Sll, SllError};
}
