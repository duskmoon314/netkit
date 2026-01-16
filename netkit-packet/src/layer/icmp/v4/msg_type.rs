//! ICMPv4 message type and code definitions.
//!
//! See the [parent module](super) for implementation status of all ICMP message types.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

/// ICMPv4 message types
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
pub enum Icmpv4Type {
    /// Echo Reply
    EchoReply = 0,

    /// Destination Unreachable
    DestinationUnreachable = 3,

    /// Source Quench (Deprecated)
    SourceQuench = 4,

    /// Redirect Message
    Redirect = 5,

    /// Echo Request
    EchoRequest = 8,

    /// Router Advertisement
    RouterAdvertisement = 9,

    /// Router Solicitation
    RouterSolicitation = 10,

    /// Time Exceeded
    TimeExceeded = 11,

    /// Parameter Problem
    ParameterProblem = 12,

    /// Timestamp
    Timestamp = 13,

    /// Timestamp Reply
    TimestampReply = 14,

    /// Information Request (Deprecated)
    InformationRequest = 15,

    /// Information Reply (Deprecated)
    InformationReply = 16,

    /// Address Mask Request (Deprecated)
    AddressMaskRequest = 17,

    /// Address Mask Reply (Deprecated)
    AddressMaskReply = 18,

    /// Traceroute (Deprecated)
    Traceroute = 30,

    /// Extended Echo Request
    ExtendedEchoRequest = 42,

    /// Extended Echo Reply
    ExtendedEchoReply = 43,

    /// Reserved or unknown ICMP type
    #[num_enum(catch_all)]
    Reserved(u8),
}

crate::impl_target!(frominto, Icmpv4Type, u8);

/// Destination Unreachable codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DestUnreachCode {
    /// Network Unreachable
    NetUnreachable = 0,
    /// Host Unreachable
    HostUnreachable = 1,
    /// Protocol Unreachable
    ProtocolUnreachable = 2,
    /// Port Unreachable
    PortUnreachable = 3,
    /// Fragmentation Needed and DF Set
    FragmentationNeeded = 4,
    /// Source Route Failed
    SourceRouteFailed = 5,
    /// Destination Network Unknown
    DestNetworkUnknown = 6,
    /// Destination Host Unknown
    DestHostUnknown = 7,
    /// Source Host Isolated
    SourceHostIsolated = 8,
    /// Communication with Destination Network Administratively Prohibited
    NetworkProhibited = 9,
    /// Communication with Destination Host Administratively Prohibited
    HostProhibited = 10,
    /// Network Unreachable for ToS
    NetworkUnreachableTos = 11,
    /// Host Unreachable for ToS
    HostUnreachableTos = 12,
    /// Communication Administratively Prohibited
    CommunicationProhibited = 13,
    /// Host Precedence Violation
    HostPrecedenceViolation = 14,
    /// Precedence Cutoff in Effect
    PrecedenceCutoff = 15,
}

impl TryFrom<u8> for DestUnreachCode {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DestUnreachCode::NetUnreachable),
            1 => Ok(DestUnreachCode::HostUnreachable),
            2 => Ok(DestUnreachCode::ProtocolUnreachable),
            3 => Ok(DestUnreachCode::PortUnreachable),
            4 => Ok(DestUnreachCode::FragmentationNeeded),
            5 => Ok(DestUnreachCode::SourceRouteFailed),
            6 => Ok(DestUnreachCode::DestNetworkUnknown),
            7 => Ok(DestUnreachCode::DestHostUnknown),
            8 => Ok(DestUnreachCode::SourceHostIsolated),
            9 => Ok(DestUnreachCode::NetworkProhibited),
            10 => Ok(DestUnreachCode::HostProhibited),
            11 => Ok(DestUnreachCode::NetworkUnreachableTos),
            12 => Ok(DestUnreachCode::HostUnreachableTos),
            13 => Ok(DestUnreachCode::CommunicationProhibited),
            14 => Ok(DestUnreachCode::HostPrecedenceViolation),
            15 => Ok(DestUnreachCode::PrecedenceCutoff),
            _ => Err(value),
        }
    }
}

/// Time Exceeded codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TimeExceededCode {
    /// TTL Exceeded in Transit
    TtlExceeded = 0,
    /// Fragment Reassembly Time Exceeded
    FragmentReassembly = 1,
}

impl TryFrom<u8> for TimeExceededCode {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TimeExceededCode::TtlExceeded),
            1 => Ok(TimeExceededCode::FragmentReassembly),
            _ => Err(value),
        }
    }
}

/// Redirect codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RedirectCode {
    /// Redirect for Network
    Network = 0,
    /// Redirect for Host
    Host = 1,
    /// Redirect for ToS and Network
    TosNetwork = 2,
    /// Redirect for ToS and Host
    TosHost = 3,
}

impl TryFrom<u8> for RedirectCode {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RedirectCode::Network),
            1 => Ok(RedirectCode::Host),
            2 => Ok(RedirectCode::TosNetwork),
            3 => Ok(RedirectCode::TosHost),
            _ => Err(value),
        }
    }
}
