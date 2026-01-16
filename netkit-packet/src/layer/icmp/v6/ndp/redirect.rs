//! ICMPv6 Redirect message (NDP).

use crate::{field_spec, prelude::*};
use core::net::Ipv6Addr;

field_spec!(ReservedSpec, u32, u32);
field_spec!(TargetAddressSpec, Ipv6Addr, u128);
field_spec!(DestinationAddressSpec, Ipv6Addr, u128);

/// ICMPv6 Redirect message (Type 137).
///
/// Routers send Redirect messages to inform a host of a better first-hop node
/// on the path to a destination. Hosts update their routing information accordingly.
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
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                     Destination Address                       +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// **Type**: 137
/// **Code**: 0
///
/// **Target Address**: The IPv6 address that is a better first hop to use for
/// the destination. Can be the same as the destination address if the redirect
/// is to inform that the destination is a neighbor.
///
/// **Destination Address**: The IPv6 address of the destination that is redirected
///
/// **Options**: Possible options include Target Link-Layer Address and Redirected Header
///
/// Defined in RFC 4861 Section 4.5.
pub struct Redirect<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Redirect<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length (without options).
    pub const MIN_LENGTH: usize = 40;

    /// Field range for reserved field.
    pub const FIELD_RESERVED: core::ops::Range<usize> = 4..8;
    /// Field range for target address.
    pub const FIELD_TARGET_ADDRESS: core::ops::Range<usize> = 8..24;
    /// Field range for destination address.
    pub const FIELD_DESTINATION_ADDRESS: core::ops::Range<usize> = 24..40;
    /// Field range for options.
    pub const FIELD_OPTIONS: core::ops::RangeFrom<usize> = 40..;

    /// Create from ICMPv6 packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 40 bytes.
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

    /// Get the target address (better first hop).
    #[inline]
    pub fn target_address(&self) -> FieldRef<'_, TargetAddressSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_TARGET_ADDRESS])
    }

    /// Get the destination address (address being redirected).
    #[inline]
    pub fn destination_address(&self) -> FieldRef<'_, DestinationAddressSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_DESTINATION_ADDRESS])
    }

    /// Get the options field (NDP options).
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_OPTIONS]
    }
}

impl<T> Redirect<T>
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

    /// Get mutable access to destination address.
    #[inline]
    pub fn destination_address_mut(&mut self) -> FieldMut<'_, DestinationAddressSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_DESTINATION_ADDRESS])
    }

    /// Get mutable access to options field.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_OPTIONS]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Redirect<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Redirect<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_parse() {
        let data = vec![
            0x89, 0x00, // type=137, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // reserved
            // Target address: fe80::1
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination address: fe80::2
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let msg = Redirect::new(&data[..]).unwrap();
        assert_eq!(
            msg.target_address().get(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            msg.destination_address().get(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)
        );
    }

    #[test]
    fn test_redirect_mutation() {
        let mut data = vec![
            0x89, 0x00, // type=137, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // reserved
            // Target address (initially zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // Destination address (initially zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut msg = Redirect::new(&mut data[..]).unwrap();
        msg.target_address_mut()
            .set(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        msg.destination_address_mut()
            .set(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        assert_eq!(
            msg.target_address().get(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            msg.destination_address().get(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
        );
    }
}
