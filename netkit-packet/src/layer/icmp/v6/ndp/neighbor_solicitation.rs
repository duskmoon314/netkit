//! ICMPv6 Neighbor Solicitation message (NDP).

use crate::{field_spec, prelude::*};
use core::net::Ipv6Addr;

field_spec!(ReservedSpec, u32, u32);
field_spec!(TargetAddressSpec, Ipv6Addr, u128);

/// ICMPv6 Neighbor Solicitation message (Type 135).
///
/// Neighbor Solicitations are used by nodes to determine the link-layer address
/// of a neighbor, or to verify that a neighbor is still reachable via a cached
/// link-layer address.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Target Address                          +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// **Type**: 135
/// **Code**: 0
///
/// **Target Address**: The IPv6 address of the target of the solicitation
///
/// **Options**: Possible options include Source Link-Layer Address
///
/// Defined in RFC 4861 Section 4.3.
pub struct NeighborSolicitation<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> NeighborSolicitation<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length (without options).
    pub const MIN_LENGTH: usize = 24;

    /// Field range for reserved field.
    pub const FIELD_RESERVED: core::ops::Range<usize> = 4..8;
    /// Field range for target address.
    pub const FIELD_TARGET_ADDRESS: core::ops::Range<usize> = 8..24;
    /// Field range for options.
    pub const FIELD_OPTIONS: core::ops::RangeFrom<usize> = 24..;

    /// Create from ICMPv6 packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 24 bytes.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Create from ICMPv6 packet data with validation.
    #[inline]
    pub fn new(data: T) -> Option<Self> {
        if data.as_ref().len() >= Self::MIN_LENGTH {
            Some(unsafe { Self::new_unchecked(data) })
        } else {
            None
        }
    }

    /// Get the target address.
    #[inline]
    pub fn target_address(&self) -> FieldRef<'_, TargetAddressSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_TARGET_ADDRESS])
    }

    /// Get the options field (NDP options).
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_OPTIONS]
    }
}

impl<T> NeighborSolicitation<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to the reserved field.
    #[inline]
    pub fn reserved_mut(&mut self) -> FieldMut<'_, ReservedSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_RESERVED])
    }

    /// Get mutable access to target address.
    #[inline]
    pub fn target_address_mut(&mut self) -> FieldMut<'_, TargetAddressSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_TARGET_ADDRESS])
    }

    /// Get mutable access to options field.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_OPTIONS]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for NeighborSolicitation<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for NeighborSolicitation<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighbor_solicitation_parse() {
        let data = vec![
            0x87, 0x00, // type=135, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // reserved
            // Target address: fe80::1
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let msg = NeighborSolicitation::new(&data[..]).unwrap();
        let target = msg.target_address().get();
        assert_eq!(target, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_neighbor_solicitation_mutation() {
        let mut data = vec![
            0x87, 0x00, // type=135, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // reserved
            // Target address (initially zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut msg = NeighborSolicitation::new(&mut data[..]).unwrap();
        msg.target_address_mut()
            .set(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        assert_eq!(
            msg.target_address().get(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
        );
    }
}
