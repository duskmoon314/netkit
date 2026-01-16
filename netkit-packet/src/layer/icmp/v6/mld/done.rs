//! ICMPv6 Multicast Listener Done message (MLD).

use crate::{field_spec, prelude::*};
use core::net::Ipv6Addr;

field_spec!(MaxResponseDelaySpec, u16, u16);
field_spec!(ReservedSpec, u16, u16);
field_spec!(MulticastAddressSpec, Ipv6Addr, u128);

/// ICMPv6 Multicast Listener Done message (Type 132, MLDv1).
///
/// Nodes send Done messages to inform multicast routers that they no longer
/// wish to receive multicast packets for a specific multicast address on the
/// attached link.
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
/// **Type**: 132
/// **Code**: 0
///
/// **Maximum Response Delay**: Set to zero in Done messages.
///
/// **Multicast Address**: The IPv6 multicast address for which the node is
/// ceasing to listen.
///
/// Defined in RFC 2810 (MLDv1).
pub struct MulticastListenerDone<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> MulticastListenerDone<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum and fixed message length.
    pub const MIN_LENGTH: usize = 24;

    /// Field range for maximum response delay (should be zero).
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

    /// Get the multicast address being left.
    #[inline]
    pub fn multicast_address(&self) -> FieldRef<'_, MulticastAddressSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_MULTICAST_ADDRESS])
    }
}

impl<T> MulticastListenerDone<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to maximum response delay field.
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

impl<T: AsRef<[u8]>> AsRef<[u8]> for MulticastListenerDone<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for MulticastListenerDone<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_done_parse() {
        let data = vec![
            0x84, 0x00, // type=132, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, // max response delay (zero in done messages)
            0x00, 0x00, // reserved
            // Multicast address: ff02::1 (all nodes)
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let done = MulticastListenerDone::new(&data[..]).unwrap();
        assert_eq!(
            done.multicast_address().get(),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
        );
    }

    #[test]
    fn test_done_mutation() {
        let mut data = vec![
            0x84, 0x00, // type=132, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, // max response delay
            0x00, 0x00, // reserved
            // Multicast address (initially zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut done = MulticastListenerDone::new(&mut data[..]).unwrap();
        done.multicast_address_mut()
            .set(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 200));

        assert_eq!(
            done.multicast_address().get(),
            Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 200)
        );
    }
}
