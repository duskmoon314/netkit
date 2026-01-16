//! Multicast Listener Discovery (MLD) for ICMPv6.
//!
//! This module implements the Multicast Listener Discovery protocol (MLDv1) defined in RFC 2710.
//! MLD is used by IPv6 routers to discover multicast listeners on directly attached links,
//! and to discover which multicast addresses are of interest to those neighboring nodes.
//!
//! MLD is the IPv6 equivalent of IGMP (Internet Group Management Protocol) in IPv4.
//!
//! ## Implemented Messages
//!
//! - **Multicast Listener Query (Type 130)**: Routers query for multicast group membership
//! - **Multicast Listener Report (Type 131, MLDv1)**: Nodes report multicast group membership
//! - **Multicast Listener Done (Type 132, MLDv1)**: Nodes leave a multicast group
//!
//! ## Reference
//!
//! RFC 2710 - Multicast Listener Discovery (MLD) for IPv6

pub mod query;
pub use query::MulticastListenerQuery;

pub mod report;
pub use report::MulticastListenerReport;

pub mod done;
pub use done::MulticastListenerDone;
