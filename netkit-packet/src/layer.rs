//! The implementation of various network layers.

pub mod dns;
pub mod eth;
pub mod ip;
pub mod tcp;
pub mod udp;

/// prelude module for layer.
pub mod prelude {
    pub use super::eth::{Eth, EthAddr, EthAddrError, EthError, EthType};

    pub use super::ip::{IpProtocol, Ipv4, Ipv4Error};

    pub use super::udp::{Udp, UdpError};

    pub use super::tcp::{Tcp, TcpError};
}
