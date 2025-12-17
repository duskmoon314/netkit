//! DNS Response code

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// DNS Response code
///
/// Only the lower 4 bits are used in DNS header
/// The higher 12 bits are used for some RR types
/// See [RFC6895](https://datatracker.ietf.org/doc/html/rfc6895) for more details
// #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
pub enum DnsRCode {
    /// No error
    NoError = 0,

    /// Format error
    FormErr = 1,

    /// Server failure
    ServFail = 2,

    /// Non-Existent Domain
    NXDomain = 3,

    /// Not Implemented
    NotImp = 4,

    /// Query Refused
    Refused = 5,

    /// Name exists when it should not
    YXDomain = 6,

    /// RR Set exists when it should not
    YXRRSet = 7,

    /// RR Set that should exist does not
    NXRRSet = 8,

    /// Server Not Authoritative for zone / Not Authorized
    NotAuth = 9,

    /// Name not contained in zone
    NotZone = 10,

    /// DSO-TYPE Not Implemented
    DSOTYPENI = 11,

    /// Bad OPT Version / TSIG Signature Failure
    #[allow(non_camel_case_types)]
    BADVERS_BADSIG = 16,

    /// Key not recognized
    BADKEY = 17,

    /// Signature out of time window
    BADTIME = 18,

    /// Bad TKEY Mode
    BADMODE = 19,

    /// Duplicate key name
    BADNAME = 20,

    /// Algorithm not supported
    BADALG = 21,

    /// Bad Truncation
    BADTRUNC = 22,

    /// Bad/missing Server Cookie
    BADCOOKIE = 23,

    /// Unassigned
    #[num_enum(catch_all)]
    Unassigned(u16),

    /// Reserved, can be allocated by Standards Action
    Reserved = 65535,
}

// num_enum's catch_all does not work with derive(Default)
#[allow(clippy::derivable_impls)]
impl Default for DnsRCode {
    fn default() -> Self {
        DnsRCode::NoError
    }
}

impl From<u8> for DnsRCode {
    fn from(value: u8) -> Self {
        DnsRCode::from(value as u16)
    }
}

impl From<DnsRCode> for u8 {
    fn from(value: DnsRCode) -> Self {
        <DnsRCode as Into<u16>>::into(value) as u8
    }
}

impl_target!(frominto, DnsRCode, u16);
impl_target!(frominto, DnsRCode, u8);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{test_enum_num, test_enum_str};

    use super::*;

    #[test]
    fn rcode_str() {
        test_enum_str!(
            DnsRCode,
            NoError => "NoError",
            FormErr => "FormErr",
            ServFail => "ServFail",
            NXDomain => "NXDomain",
            NotImp => "NotImp",
            Refused => "Refused",
            YXDomain => "YXDomain",
            YXRRSet => "YXRRSet",
            NXRRSet => "NXRRSet",
            NotAuth => "NotAuth",
            NotZone => "NotZone",
            DSOTYPENI => "DSOTYPENI",
            BADVERS_BADSIG => "BADVERS_BADSIG",
            BADKEY => "BADKEY",
            BADTIME => "BADTIME",
            BADMODE => "BADMODE",
            BADNAME => "BADNAME",
            BADALG => "BADALG",
            BADTRUNC => "BADTRUNC",
            BADCOOKIE => "BADCOOKIE",
            Reserved => "Reserved",
        );
    }

    #[test]
    fn rcode_num() {
        test_enum_num!(
            DnsRCode : u16,
            NoError => 0,
            FormErr => 1,
            ServFail => 2,
            NXDomain => 3,
            NotImp => 4,
            Refused => 5,
            YXDomain => 6,
            YXRRSet => 7,
            NXRRSet => 8,
            NotAuth => 9,
            NotZone => 10,
            DSOTYPENI => 11,
            BADVERS_BADSIG => 16,
            BADKEY => 17,
            BADTIME => 18,
            BADMODE => 19,
            BADNAME => 20,
            BADALG => 21,
            BADTRUNC => 22,
            BADCOOKIE => 23,
        );
    }
}
