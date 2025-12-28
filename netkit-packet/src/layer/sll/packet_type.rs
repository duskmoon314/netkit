//! SLL packet type field

use num_enum::IntoPrimitive;
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// The packet type field values for SLL.
///
/// Indicates the direction and destination of the packet.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, IntoPrimitive, EnumString, Display, AsRefStr)]
#[repr(u16)]
pub enum PacketType {
    /// The packet was specifically sent to us.
    SentToUs = 0,
    /// The packet was broadcast by somebody else.
    Broadcast = 1,
    /// The packet was multicast but not broadcast.
    Multicast = 2,
    /// The packet was sent to somebody else by somebody else.
    OtherHost = 3,
    /// The packet was sent by us.
    SentByUs = 4,
}

impl From<u16> for PacketType {
    fn from(value: u16) -> Self {
        match value {
            0 => PacketType::SentToUs,
            1 => PacketType::Broadcast,
            2 => PacketType::Multicast,
            3 => PacketType::OtherHost,
            4 => PacketType::SentByUs,
            _ => panic!("Invalid value for PacketType: {}", value),
        }
    }
}

impl_target!(frominto, PacketType, u16);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::test_enum_str;

    use super::*;

    #[test]
    fn packet_type_str() {
        test_enum_str!(
            PacketType,
            SentToUs => "SentToUs",
            Broadcast => "Broadcast",
            Multicast => "Multicast",
            OtherHost => "OtherHost",
            SentByUs => "SentByUs",
        );
    }

    #[test]
    fn packet_type_from_u16() {
        assert_eq!(PacketType::from(0), PacketType::SentToUs);
        assert_eq!(PacketType::from(1), PacketType::Broadcast);
        assert_eq!(PacketType::from(2), PacketType::Multicast);
        assert_eq!(PacketType::from(3), PacketType::OtherHost);
        assert_eq!(PacketType::from(4), PacketType::SentByUs);
    }

    #[test]
    fn packet_type_into_u16() {
        let val: u16 = PacketType::SentToUs.into();
        assert_eq!(val, 0);
        let val: u16 = PacketType::Broadcast.into();
        assert_eq!(val, 1);
    }
}
