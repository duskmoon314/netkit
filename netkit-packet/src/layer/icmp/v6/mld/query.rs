//! ICMPv6 Multicast Listener Query message (MLD).

use crate::{field_spec, prelude::*};
use core::net::Ipv6Addr;

field_spec!(MaxResponseDelaySpec, u16, u16);
field_spec!(ReservedSpec, u16, u16);
field_spec!(MulticastAddressSpec, Ipv6Addr, u128);

/// ICMPv6 Multicast Listener Query message (Type 130).
///
/// Multicast routers send Query messages to discover which multicast addresses
/// have listeners on attached links. Queries are sent periodically to refresh
/// knowledge of group membership on each link.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Maximum Response Delay    |          Reserved             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Multicast Address                       +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// **Type**: 130
/// **Code**: 0
///
/// **Maximum Response Delay**: Maximum time (in milliseconds) before sending a
/// responding Report. Used only in Query messages; zero in Report and Done messages.
///
/// **Multicast Address**: For a General Query, this is set to zero (::). For a
/// Multicast-Address-Specific Query, this is set to the multicast address being queried.
///
/// Defined in RFC 2810 (MLDv1).
pub struct MulticastListenerQuery<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> MulticastListenerQuery<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum and fixed message length.
    pub const MIN_LENGTH: usize = 24;

    /// Field range for maximum response delay.
    pub const FIELD_MAX_RESPONSE_DELAY: core::ops::Range<usize> = 4..6;
    /// Field range for reserved field.
    pub const FIELD_RESERVED: core::ops::Range<usize> = 6..8;
    /// Field range for multicast address.
    pub const FIELD_MULTICAST_ADDRESS: core::ops::Range<usize> = 8..24;

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

    /// Get the maximum response delay (in milliseconds).
    #[inline]
    pub fn max_response_delay(&self) -> FieldRef<'_, MaxResponseDelaySpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_MAX_RESPONSE_DELAY])
    }

    /// Get the multicast address being queried.
    ///
    /// Returns the IPv6 unspecified address (::) for a General Query,
    /// or a specific multicast address for a Multicast-Address-Specific Query.
    #[inline]
    pub fn multicast_address(&self) -> FieldRef<'_, MulticastAddressSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_MULTICAST_ADDRESS])
    }

    /// Check if this is a General Query.
    ///
    /// A General Query has the multicast address set to the unspecified address (::).
    #[inline]
    pub fn is_general_query(&self) -> bool {
        self.multicast_address().get() == Ipv6Addr::UNSPECIFIED
    }
}

impl<T> MulticastListenerQuery<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to maximum response delay.
    #[inline]
    pub fn max_response_delay_mut(&mut self) -> FieldMut<'_, MaxResponseDelaySpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_MAX_RESPONSE_DELAY])
    }

    /// Get mutable access to reserved field.
    #[inline]
    pub fn reserved_mut(&mut self) -> FieldMut<'_, ReservedSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_RESERVED])
    }

    /// Get mutable access to multicast address.
    #[inline]
    pub fn multicast_address_mut(&mut self) -> FieldMut<'_, MulticastAddressSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_MULTICAST_ADDRESS])
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for MulticastListenerQuery<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for MulticastListenerQuery<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_general_query() {
        let data = vec![
            0x82, 0x00, // type=130, code=0
            0x00, 0x00, // checksum
            0x27, 0x10, // max response delay = 10000ms
            0x00, 0x00, // reserved
            // Multicast address: :: (unspecified for general query)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let query = MulticastListenerQuery::new(&data[..]).unwrap();
        assert_eq!(query.max_response_delay().get(), 10000);
        assert_eq!(query.multicast_address().get(), Ipv6Addr::UNSPECIFIED);
        assert!(query.is_general_query());
    }

    #[test]
    fn test_specific_query() {
        let data = vec![
            0x82, 0x00, // type=130, code=0
            0x00, 0x00, // checksum
            0x27, 0x10, // max response delay = 10000ms
            0x00, 0x00, // reserved
            // Multicast address: ff02::1 (all nodes)
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let query = MulticastListenerQuery::new(&data[..]).unwrap();
        assert_eq!(query.max_response_delay().get(), 10000);
        assert_eq!(
            query.multicast_address().get(),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
        );
        assert!(!query.is_general_query());
    }

    #[test]
    fn test_query_mutation() {
        let mut data = vec![
            0x82, 0x00, // type=130, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, // max response delay
            0x00, 0x00, // reserved
            // Multicast address (initially zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut query = MulticastListenerQuery::new(&mut data[..]).unwrap();
        query.max_response_delay_mut().set(5000);
        query
            .multicast_address_mut()
            .set(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));

        assert_eq!(query.max_response_delay().get(), 5000);
        assert_eq!(
            query.multicast_address().get(),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
        );
    }
}
