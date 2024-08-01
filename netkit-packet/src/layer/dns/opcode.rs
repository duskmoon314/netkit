//! DNS OpCode

// Some of the variants are deprecated, so we need to allow deprecated items
#![allow(deprecated)]
#![allow(clippy::deprecated_semver)]

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// DNS Operation Code
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[repr(u8)]
#[non_exhaustive]
pub enum DnsOpCode {
    /// Query
    Query = 0,

    /// Inverse Query
    #[deprecated(since = "RFC3425")]
    IQuery = 1,

    /// Status
    Status = 2,

    /// Notify
    Notify = 4,

    /// Update
    Update = 5,

    /// DNS Stateful Operations
    DSO = 6,

    /// Unassigned
    #[num_enum(catch_all)]
    Unassigned(u8),
}

// num_enum's catch_all does not work with derive(Default)
#[allow(clippy::derivable_impls)]
impl Default for DnsOpCode {
    fn default() -> Self {
        DnsOpCode::Query
    }
}

impl_target!(frominto, DnsOpCode, u8);

#[cfg(test)]
mod tests {
    use crate::{test_enum_num, test_enum_str};

    use super::*;
    use std::str::FromStr;

    #[test]
    fn opcode_str() {
        test_enum_str!(
            DnsOpCode,
            Query => "Query",
            IQuery => "IQuery",
            Status => "Status",
            Notify => "Notify",
            Update => "Update",
            DSO => "DSO",
        );
    }

    #[test]
    fn opcode_num() {
        test_enum_num!(
            DnsOpCode : u8,
            Query => 0,
            IQuery => 1,
            Status => 2,
            Notify => 4,
            Update => 5,
            DSO => 6,
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn opcode_serde() {
        let opcode = DnsOpCode::default();
        let serialized = serde_json::to_string(&opcode).unwrap();
        assert_eq!(serialized, r#""Query""#);
        let deserialized: DnsOpCode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, opcode);
    }
}
