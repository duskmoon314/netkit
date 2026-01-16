//! Neighbor Discovery Protocol (NDP) for ICMPv6.
//!
//! This module implements the core Neighbor Discovery Protocol messages defined in RFC 4861.
//! NDP is a fundamental protocol in IPv6 that replaces and enhances several IPv4 protocols
//! including ARP, ICMP Router Discovery, and ICMP Redirect.
//!
//! ## Implemented Messages
//!
//! - **Router Solicitation (Type 133)**: Hosts request routers to generate Router Advertisements
//! - **Router Advertisement (Type 134)**: Routers advertise their presence and network parameters
//! - **Neighbor Solicitation (Type 135)**: Address resolution and neighbor reachability detection
//! - **Neighbor Advertisement (Type 136)**: Response to Neighbor Solicitation or unsolicited announcement
//! - **Redirect (Type 137)**: Routers inform hosts of better first-hop routers
//!
//! ## Reference
//!
//! RFC 4861 - Neighbor Discovery for IP version 6 (IPv6)

pub mod router_solicitation;
pub use router_solicitation::RouterSolicitation;

pub mod router_advertisement;
pub use router_advertisement::RouterAdvertisement;

pub mod neighbor_solicitation;
pub use neighbor_solicitation::NeighborSolicitation;

pub mod neighbor_advertisement;
pub use neighbor_advertisement::NeighborAdvertisement;

pub mod redirect;
pub use redirect::Redirect;
