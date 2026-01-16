//! ICMP (Internet Control Message Protocol) layer.
//!
//! This module provides comprehensive ICMP support for both ICMPv4 and ICMPv6
//! with message-specific types.
//!
//! # ICMPv4
//!
//! See [`v4`] module for implementation details and status.
//!
//! # ICMPv6
//!
//! See [`v6`] module for implementation details and status.

// ICMPv4
pub mod v4;
pub use v4::{
    // Message type codes
    DestUnreachCode,
    // Error messages
    IcmpDestUnreach,
    // Informational messages
    IcmpEcho,
    IcmpExtendedEchoReply,
    IcmpExtendedEchoRequest,
    IcmpParamProblem,
    IcmpRedirect,
    IcmpRouterAdvertisement,
    IcmpRouterSolicitation,
    IcmpTimeExceeded,
    // Core types
    Icmpv4,
    // Builders
    Icmpv4EchoBuilder,
    Icmpv4Error,
    Icmpv4Timestamp,
    Icmpv4Type,
    RedirectCode,
    TimeExceededCode,
};

// ICMPv6
pub mod v6;
pub use v6::{
    // Core types
    Icmpv6,
    // Error messages
    Icmpv6DestUnreach,
    // Informational messages
    Icmpv6Echo,
    Icmpv6Error,
    Icmpv6PacketTooBig,
    Icmpv6ParamProblem,
    Icmpv6TimeExceeded,
    Icmpv6Type,
    // MLD (Multicast Listener Discovery)
    MulticastListenerDone,
    MulticastListenerQuery,
    MulticastListenerReport,
    // NDP (Neighbor Discovery Protocol)
    NeighborAdvertisement,
    NeighborSolicitation,
    Redirect,
    RouterAdvertisement,
    RouterSolicitation,
};
