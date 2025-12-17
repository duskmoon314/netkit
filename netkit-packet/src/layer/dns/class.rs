//! Dns Class

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// Dns Class
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
pub enum DnsClass {
    /// Internet
    #[strum(serialize = "Internet", serialize = "IN")]
    Internet = 1,
    /// Chaos
    #[strum(serialize = "Chaos", serialize = "CH")]
    Chaos = 3,
    /// Hesiod
    #[strum(serialize = "Hesiod", serialize = "HS")]
    Hesiod = 4,
    /// None
    #[strum(serialize = "NONE", serialize = "None")]
    None = 254,
    /// Any
    #[strum(serialize = "ANY", serialize = "Any", serialize = "*")]
    Any = 255,

    /// Reserved
    #[num_enum(catch_all)]
    Reserved(u16),
}

impl Default for DnsClass {
    fn default() -> Self {
        Self::Reserved(0)
    }
}

impl_target!(frominto, DnsClass, u16);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{test_enum_num, test_enum_str};

    use super::*;

    #[test]
    fn class_str() {
        test_enum_str!(
            DnsClass,
            Internet => "Internet",
            Chaos => "Chaos",
            Hesiod => "Hesiod",
            None => "None",
            Any => "Any",
        );
    }

    #[test]
    fn class_num() {
        test_enum_num!(
            DnsClass: u16,
            Internet => 1,
            Chaos => 3,
            Hesiod => 4,
            None => 254,
            Any => 255,
        );
    }
}
