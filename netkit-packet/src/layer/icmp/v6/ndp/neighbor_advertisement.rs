//! ICMPv6 Neighbor Advertisement message (NDP).

use crate::{field_spec, prelude::*};
use core::net::Ipv6Addr;

field_spec!(FlagsSpec, u32, u32);
field_spec!(TargetAddressSpec, Ipv6Addr, u128);

/// ICMPv6 Neighbor Advertisement message (Type 136).
///
/// Neighbor Advertisements are used by nodes to respond to Neighbor Solicitations
/// or to announce link-layer address changes.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|S|O|                     Reserved                            |
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
/// **Type**: 136
/// **Code**: 0
///
/// **Flags**:
/// - R (Router): When set, indicates that the sender is a router
/// - S (Solicited): When set, indicates that the advertisement was sent in
///   response to a Neighbor Solicitation
/// - O (Override): When set, indicates that the advertisement should override
///   an existing cache entry
///
/// **Target Address**: The IPv6 address of the target (i.e., the node responding)
///
/// **Options**: Possible options include Target Link-Layer Address
///
/// Defined in RFC 4861 Section 4.4.
pub struct NeighborAdvertisement<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> NeighborAdvertisement<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length (without options).
    pub const MIN_LENGTH: usize = 24;

    /// Field range for flags and reserved.
    pub const FIELD_FLAGS: core::ops::Range<usize> = 4..8;
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

    /// Get the flags field.
    #[inline]
    pub fn flags(&self) -> FieldRef<'_, FlagsSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_FLAGS])
    }

    /// Check if the Router flag (R) is set.
    #[inline]
    pub fn router(&self) -> bool {
        self.flags().get() & 0x80000000 != 0
    }

    /// Check if the Solicited flag (S) is set.
    #[inline]
    pub fn solicited(&self) -> bool {
        self.flags().get() & 0x40000000 != 0
    }

    /// Check if the Override flag (O) is set.
    #[inline]
    pub fn override_flag(&self) -> bool {
        self.flags().get() & 0x20000000 != 0
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

impl<T> NeighborAdvertisement<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to flags field.
    #[inline]
    pub fn flags_mut(&mut self) -> FieldMut<'_, FlagsSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_FLAGS])
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

impl<T: AsRef<[u8]>> AsRef<[u8]> for NeighborAdvertisement<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for NeighborAdvertisement<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighbor_advertisement_parse() {
        let data = vec![
            0x88, 0x00, // type=136, code=0
            0x00, 0x00, // checksum
            0x60, 0x00, 0x00, 0x00, // flags (R=0, S=1, O=1)
            // Target address: fe80::1
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let msg = NeighborAdvertisement::new(&data[..]).unwrap();
        assert!(!msg.router());
        assert!(msg.solicited());
        assert!(msg.override_flag());
        assert_eq!(
            msg.target_address().get(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
        );
    }

    #[test]
    fn test_neighbor_advertisement_router_flag() {
        let data = vec![
            0x88, 0x00, // type=136, code=0
            0x00, 0x00, // checksum
            0x80, 0x00, 0x00, 0x00, // flags (R=1, S=0, O=0)
            // Target address
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let msg = NeighborAdvertisement::new(&data[..]).unwrap();
        assert!(msg.router());
        assert!(!msg.solicited());
        assert!(!msg.override_flag());
    }
}
