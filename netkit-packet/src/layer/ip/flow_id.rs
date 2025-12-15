//! Flow Id
//!
//! This module contains a helper struct for different flow id types.

use std::net::{IpAddr, Ipv4Addr};

use crate::prelude::IpProtocol;

/// Flow Id
///
/// Different types of flow ids:
/// - Single Ip address
/// - 2-tuple: Src Ip address + Dst Ip address
/// - 2-tuple-sym: Ip address pair (src/dst interchangeable)
/// - 3-tuple: Src Ip address + Dst Ip address + Protocol
/// - 3-tuple-sym: Ip address pair + Protocol (src/dst interchangeable)
/// - 4-tuple: Src Ip address + Dst Ip address + Src Port + Dst Port
/// - 4-tuple-sym: Ip address pair + Src Port + Dst Port (src/dst interchangeable)
/// - 5-tuple: Src Ip address + Dst Ip address + Src Port + Dst Port + Protocol
/// - 5-tuple-sym: Ip address pair + Src Port + Dst Port + Protocol (src/dst interchangeable)
#[derive(Debug, Clone, Copy)]
pub enum FlowId {
    /// Single Ip address
    Ip(IpAddr),

    /// 2-tuple: Src Ip address + Dst Ip address
    Tuple2(IpAddr, IpAddr),

    /// 2-tuple-sym: Ip address pair (src/dst interchangeable)
    Tuple2Sym(IpAddr, IpAddr),

    /// 3-tuple: Src Ip address + Dst Ip address + Protocol
    Tuple3(IpAddr, IpAddr, IpProtocol),

    /// 3-tuple-sym: Ip address pair + Protocol (src/dst interchangeable)
    Tuple3Sym(IpAddr, IpAddr, IpProtocol),

    /// 4-tuple: Src Ip address + Dst Ip address + Src Port + Dst Port
    Tuple4(IpAddr, IpAddr, u16, u16),

    /// 4-tuple-sym: Ip address pair + Src Port + Dst Port (src/dst interchangeable)
    Tuple4Sym(IpAddr, IpAddr, u16, u16),

    /// 5-tuple: Src Ip address + Dst Ip address + Src Port + Dst Port + Protocol
    Tuple5(IpAddr, IpAddr, u16, u16, IpProtocol),

    /// 5-tuple-sym: Ip address pair + Src Port + Dst Port + Protocol (src/dst interchangeable)
    Tuple5Sym(IpAddr, IpAddr, u16, u16, IpProtocol),
}

impl FlowId {
    /// Create a 2-tuple FlowId
    pub fn from_tuple2(src: impl Into<IpAddr>, dst: impl Into<IpAddr>, sym: bool) -> Self {
        if sym {
            FlowId::Tuple2Sym(src.into(), dst.into())
        } else {
            FlowId::Tuple2(src.into(), dst.into())
        }
    }

    /// Create a 3-tuple FlowId
    pub fn from_tuple3(
        src: impl Into<IpAddr>,
        dst: impl Into<IpAddr>,
        proto: impl Into<IpProtocol>,
        sym: bool,
    ) -> Self {
        if sym {
            let src = src.into();
            let dst = dst.into();
            if src <= dst {
                FlowId::Tuple3Sym(src, dst, proto.into())
            } else {
                FlowId::Tuple3Sym(dst, src, proto.into())
            }
        } else {
            FlowId::Tuple3(src.into(), dst.into(), proto.into())
        }
    }

    /// Create a 4-tuple FlowId
    pub fn from_tuple4(
        src: impl Into<IpAddr>,
        dst: impl Into<IpAddr>,
        sport: u16,
        dport: u16,
        sym: bool,
    ) -> Self {
        if sym {
            let src = src.into();
            let dst = dst.into();
            if src <= dst {
                FlowId::Tuple4Sym(src, dst, sport, dport)
            } else {
                FlowId::Tuple4Sym(dst, src, dport, sport)
            }
        } else {
            FlowId::Tuple4(src.into(), dst.into(), sport, dport)
        }
    }

    /// Create a 5-tuple FlowId
    pub fn from_tuple5(
        src: impl Into<IpAddr>,
        dst: impl Into<IpAddr>,
        sport: u16,
        dport: u16,
        proto: impl Into<IpProtocol>,
        sym: bool,
    ) -> Self {
        if sym {
            let src = src.into();
            let dst = dst.into();
            if src <= dst {
                FlowId::Tuple5Sym(src, dst, sport, dport, proto.into())
            } else {
                FlowId::Tuple5Sym(dst, src, dport, sport, proto.into())
            }
        } else {
            FlowId::Tuple5(src.into(), dst.into(), sport, dport, proto.into())
        }
    }
}

impl PartialEq for FlowId {
    fn eq(&self, other: &Self) -> bool {
        use FlowId::*;

        match (*self, *other) {
            (Ip(l_src), Ip(r_src)) => l_src == r_src,

            (Tuple2(l_src, l_dst), Tuple2(r_src, r_dst)) => l_src == r_src && l_dst == r_dst,

            (Tuple2Sym(l_src, l_dst), Tuple2Sym(r_src, r_dst)) => {
                (l_src == r_src && l_dst == r_dst) || (l_src == r_dst && l_dst == r_src)
            }

            (Tuple3(l_src, l_dst, l_proto), Tuple3(r_src, r_dst, r_proto)) => {
                l_src == r_src && l_dst == r_dst && l_proto == r_proto
            }

            (Tuple3Sym(l_src, l_dst, l_proto), Tuple3Sym(r_src, r_dst, r_proto)) => {
                (l_src == r_src && l_dst == r_dst || l_src == r_dst && l_dst == r_src)
                    && l_proto == r_proto
            }

            (Tuple4(l_src, l_dst, l_sport, l_dport), Tuple4(r_src, r_dst, r_sport, r_dport)) => {
                l_src == r_src && l_dst == r_dst && l_sport == r_sport && l_dport == r_dport
            }

            (
                Tuple4Sym(l_src, l_dst, l_sport, l_dport),
                Tuple4Sym(r_src, r_dst, r_sport, r_dport),
            ) => {
                (l_src == r_src && l_dst == r_dst && l_sport == r_sport && l_dport == r_dport)
                    || (l_src == r_dst
                        && l_dst == r_src
                        && l_sport == r_dport
                        && l_dport == r_sport)
            }

            (
                Tuple5(l_src, l_dst, l_sport, l_dport, l_proto),
                Tuple5(r_src, r_dst, r_sport, r_dport, r_proto),
            ) => {
                l_src == r_src
                    && l_dst == r_dst
                    && l_sport == r_sport
                    && l_dport == r_dport
                    && l_proto == r_proto
            }

            (
                Tuple5Sym(l_src, l_dst, l_sport, l_dport, l_proto),
                Tuple5Sym(r_src, r_dst, r_sport, r_dport, r_proto),
            ) => {
                (l_src == r_src
                    && l_dst == r_dst
                    && l_sport == r_sport
                    && l_dport == r_dport
                    && l_proto == r_proto)
                    || (l_src == r_dst
                        && l_dst == r_src
                        && l_sport == r_dport
                        && l_dport == r_sport
                        && l_proto == r_proto)
            }

            _ => false,
        }
    }
}

impl Eq for FlowId {}

impl std::hash::Hash for FlowId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        use FlowId::*;

        // For symmetric variants, normalize the ordering before hashing
        // to ensure that Tuple2Sym(A, B) and Tuple2Sym(B, A) hash to the same value
        match self {
            Ip(addr) => {
                0u8.hash(state);
                addr.hash(state);
            }
            Tuple2(src, dst) => {
                1u8.hash(state);
                src.hash(state);
                dst.hash(state);
            }
            Tuple2Sym(src, dst) => {
                2u8.hash(state);
                if src <= dst {
                    src.hash(state);
                    dst.hash(state);
                } else {
                    dst.hash(state);
                    src.hash(state);
                }
            }
            Tuple3(src, dst, proto) => {
                3u8.hash(state);
                src.hash(state);
                dst.hash(state);
                proto.hash(state);
            }
            Tuple3Sym(src, dst, proto) => {
                4u8.hash(state);
                if src <= dst {
                    src.hash(state);
                    dst.hash(state);
                } else {
                    dst.hash(state);
                    src.hash(state);
                }
                proto.hash(state);
            }
            Tuple4(src, dst, sport, dport) => {
                5u8.hash(state);
                src.hash(state);
                dst.hash(state);
                sport.hash(state);
                dport.hash(state);
            }
            Tuple4Sym(src, dst, sport, dport) => {
                6u8.hash(state);
                if src <= dst {
                    src.hash(state);
                    dst.hash(state);
                    sport.hash(state);
                    dport.hash(state);
                } else {
                    dst.hash(state);
                    src.hash(state);
                    dport.hash(state);
                    sport.hash(state);
                }
            }
            Tuple5(src, dst, sport, dport, proto) => {
                7u8.hash(state);
                src.hash(state);
                dst.hash(state);
                sport.hash(state);
                dport.hash(state);
                proto.hash(state);
            }
            Tuple5Sym(src, dst, sport, dport, proto) => {
                8u8.hash(state);
                if src <= dst {
                    src.hash(state);
                    dst.hash(state);
                    sport.hash(state);
                    dport.hash(state);
                } else {
                    dst.hash(state);
                    src.hash(state);
                    dport.hash(state);
                    sport.hash(state);
                }
                proto.hash(state);
            }
        }
    }
}

impl From<IpAddr> for FlowId {
    fn from(addr: IpAddr) -> Self {
        FlowId::Ip(addr)
    }
}

impl From<&IpAddr> for FlowId {
    fn from(addr: &IpAddr) -> Self {
        FlowId::Ip(*addr)
    }
}

impl From<Ipv4Addr> for FlowId {
    fn from(addr: Ipv4Addr) -> Self {
        FlowId::Ip(IpAddr::V4(addr))
    }
}

impl From<&Ipv4Addr> for FlowId {
    fn from(addr: &Ipv4Addr) -> Self {
        FlowId::Ip(IpAddr::V4(*addr))
    }
}
