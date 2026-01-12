//! ICMP (Internet Control Message Protocol) layer.
//!
//! This module provides comprehensive ICMP support with message-specific types.
//!
//! # Structure
//!
//! - `v4`: ICMPv4 implementation
//!   - `msg_type`: Message type enums and codes
//!   - `echo`: Echo Request/Reply messages
//!   - `dest_unreach`: Destination Unreachable messages
//!   - `time_exceeded`: Time Exceeded messages
//!   - `redirect`: Redirect messages
//!   - `param_problem`: Parameter Problem messages
//! - `v6`: ICMPv6 implementation (simplified)

pub mod v4;
pub use v4::{
    DestUnreachCode, IcmpDestUnreach, IcmpEcho, IcmpParamProblem, IcmpRedirect, IcmpTimeExceeded,
    Icmpv4, Icmpv4EchoBuilder, Icmpv4Error, Icmpv4Type, RedirectCode, TimeExceededCode,
};

pub mod v6;
pub use v6::{Icmpv6, Icmpv6Error, Icmpv6Type};
