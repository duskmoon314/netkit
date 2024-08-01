//! Dns Resource Record Type

// Some of the variants are deprecated, so we need to allow deprecated items
#![allow(deprecated)]
#![allow(clippy::deprecated_semver)]

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// Dns Resource Record Type
#[derive(
    // core traits
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    // num_enum traits
    FromPrimitive,
    IntoPrimitive,
    // strum traits
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u16)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum DnsRrType {
    /// A host address
    A = 1,

    /// An authoritative name server
    NS = 2,

    /// A mail destination (Obsolete - use MX)
    #[deprecated(since = "RFC 1035", note = "Use MX")]
    MD = 3,

    /// A mail forwarder (Obsolete - use MX)
    #[deprecated(since = "RFC 1035", note = "Use MX")]
    MF = 4,

    /// The canonical name for an alias
    CNAME = 5,

    /// Marks the start of a zone of authority
    SOA = 6,

    /// A mailbox domain name (EXPERIMENTAL)
    MB = 7,

    /// A mail group member (EXPERIMENTAL)
    MG = 8,

    /// A mail rename domain name (EXPERIMENTAL)
    MR = 9,

    /// A null RR (EXPERIMENTAL)
    NULL = 10,

    /// A well known service description
    WKS = 11,

    /// A domain name pointer
    PTR = 12,

    /// Host Information
    HINFO = 13,

    /// Mailbox or mail list information
    MINFO = 14,

    /// Mail exchange
    MX = 15,

    /// Text strings
    TXT = 16,

    /// The Responsible Person
    RP = 17,

    AFSDB = 18,

    X25 = 19,

    ISDN = 20,

    RT = 21,

    NSAP = 22,

    NSAPPTR = 23,

    SIG = 24,

    KEY = 25,

    PX = 26,

    GPOS = 27,

    /// IP6 Address
    AAAA = 28,

    LOC = 29,

    NXT = 30,

    EID = 31,

    NIMLOC = 32,

    SRV = 33,

    ATMA = 34,

    NAPTR = 35,

    KX = 36,

    CERT = 37,

    A6 = 38,

    DNAME = 39,

    SINK = 40,

    OPT = 41,

    APL = 42,

    DS = 43,

    SSHFP = 44,

    IPSECKEY = 45,

    RRSIG = 46,

    NSEC = 47,

    DNSKEY = 48,

    DHCID = 49,

    NSEC3 = 50,

    NSEC3PARAM = 51,

    TLSA = 52,

    SMIMEA = 53,

    HIP = 55,

    NINFO = 56,

    RKEY = 57,

    TALINK = 58,

    CDS = 59,

    CDNSKEY = 60,

    OPENPGPKEY = 61,

    CSYNC = 62,

    ZONEMD = 63,

    SVCB = 64,

    HTTPS = 65,

    SPF = 99,

    UINFO = 100,

    UID = 101,

    GID = 102,

    UNSPEC = 103,

    NID = 104,

    L32 = 105,

    L64 = 106,

    LP = 107,

    EUI48 = 108,

    EUI64 = 109,

    TKEY = 249,

    TSIG = 250,

    IXFR = 251,

    AXFR = 252,

    MAILB = 253,

    MAILA = 254,

    ANY = 255,

    URI = 256,

    CAA = 257,

    AVC = 258,

    DOA = 259,

    AMTRELAY = 260,

    TA = 32768,

    DLV = 32769,

    /// Reserved
    #[num_enum(catch_all)]
    Reserved(u16),
}

impl Default for DnsRrType {
    fn default() -> Self {
        DnsRrType::Reserved(0)
    }
}

impl_target!(frominto, DnsRrType, u16);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{test_enum_num, test_enum_str};

    use super::*;

    #[test]
    fn rrtype_str() {
        test_enum_str!(
            DnsRrType,
            A => "A",
            NS => "NS",
            MD => "MD",
            MF => "MF",
            CNAME => "CNAME",
            SOA => "SOA",
            MB => "MB",
            MG => "MG",
            MR => "MR",
            NULL => "NULL",
            WKS => "WKS",
            PTR => "PTR",
            HINFO => "HINFO",
            MINFO => "MINFO",
            MX => "MX",
            TXT => "TXT",
            RP => "RP",
            AFSDB => "AFSDB",
            X25 => "X25",
            ISDN => "ISDN",
            RT => "RT",
            NSAP => "NSAP",
            NSAPPTR => "NSAPPTR",
            SIG => "SIG",
        );
    }

    #[test]
    fn rrtype_num() {
        test_enum_num!(
            DnsRrType: u16,
            A => 1,
            NS => 2,
            MD => 3,
            MF => 4,
            CNAME => 5,
            SOA => 6,
            MB => 7,
            MG => 8,
            MR => 9,
            NULL => 10,
            WKS => 11,
            PTR => 12,
            HINFO => 13,
            MINFO => 14,
            MX => 15,
            TXT => 16,
            RP => 17,
            AFSDB => 18,
            X25 => 19,
            ISDN => 20,
            RT => 21,
            NSAP => 22,
            NSAPPTR => 23,
            SIG => 24,
        );
    }
}
