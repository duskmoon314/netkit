//! The implementation of various network layers.

pub mod dns;
pub mod eth;
pub mod ip;
pub mod sll;
pub mod tcp;
pub mod udp;
pub mod vlan;

/// prelude module for layer.
pub mod prelude {
    pub use super::eth::{Eth, EthAddr, EthAddrError, EthError, EthType};

    pub use super::vlan::{Vlan, VlanError};

    pub use super::ip::{IpProtocol, Ipv4, Ipv4Error};

    pub use super::udp::{Udp, UdpError};

    pub use super::tcp::{Tcp, TcpError};

    pub use super::dns::{
        Dns, DnsClass, DnsError, DnsLabel, DnsName, DnsNameError, DnsOpCode, DnsQuestion, DnsRCode,
        DnsResourceRecord, DnsRrType,
    };

    pub use super::sll::{ArphrdType, PacketType, Sll, SllError};
}
