//! ICMPv6 message type definitions.
//!
//! See the [parent module](super) for implementation status of all ICMP message types.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

/// ICMPv6 message types
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[repr(u8)]
#[non_exhaustive]
pub enum Icmpv6Type {
    /// Destination Unreachable
    DestinationUnreachable = 1,
    /// Packet Too Big
    PacketTooBig = 2,
    /// Time Exceeded
    TimeExceeded = 3,
    /// Parameter Problem
    ParameterProblem = 4,
    /// Echo Request
    EchoRequest = 128,
    /// Echo Reply
    EchoReply = 129,
    /// Multicast Listener Query (MLD)
    MulticastListenerQuery = 130,
    /// Multicast Listener Report (MLDv1)
    MulticastListenerReport = 131,
    /// Multicast Listener Done (MLDv1)
    MulticastListenerDone = 132,
    /// Router Solicitation (NDP)
    RouterSolicitation = 133,
    /// Router Advertisement (NDP)
    RouterAdvertisement = 134,
    /// Neighbor Solicitation (NDP)
    NeighborSolicitation = 135,
    /// Neighbor Advertisement (NDP)
    NeighborAdvertisement = 136,
    /// Redirect Message
    Redirect = 137,
    /// Reserved or unknown ICMPv6 type
    #[num_enum(catch_all)]
    Reserved(u8),
}

crate::impl_target!(frominto, Icmpv6Type, u8);
