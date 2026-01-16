//! ICMPv4 Router Solicitation message.

use crate::{field_spec, prelude::*};

field_spec!(ReservedSpec, u32, u32);

/// ICMPv4 Router Solicitation message (Type 10).
///
/// Hosts broadcast Router Solicitations to prompt routers to generate Router
/// Advertisements immediately rather than waiting for the next periodic transmission.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// **Type**: 10
/// **Code**: 0
///
/// **Reserved**: Must be zero
///
/// Defined in RFC 1256.
pub struct IcmpRouterSolicitation<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpRouterSolicitation<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum and fixed message length.
    pub const MIN_LENGTH: usize = 8;

    /// Field range for reserved field.
    pub const FIELD_RESERVED: core::ops::Range<usize> = 4..8;

    /// Create from ICMP packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 8 bytes.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Create from ICMP packet data with validation.
    #[inline]
    pub fn new(data: T) -> Option<Self> {
        if data.as_ref().len() >= Self::MIN_LENGTH {
            Some(unsafe { Self::new_unchecked(data) })
        } else {
            None
        }
    }
}

impl<T> IcmpRouterSolicitation<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to the reserved field.
    #[inline]
    pub fn reserved_mut(&mut self) -> FieldMut<'_, ReservedSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_RESERVED])
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for IcmpRouterSolicitation<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for IcmpRouterSolicitation<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_solicitation_parse() {
        let data = vec![
            0x0a, 0x00, // type=10, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // reserved
        ];

        let rs = IcmpRouterSolicitation::new(&data[..]).unwrap();
        assert_eq!(rs.as_ref().len(), 8);
    }

    #[test]
    fn test_router_solicitation_mutation() {
        let mut data = vec![
            0x0a, 0x00, // type=10, code=0
            0x00, 0x00, // checksum
            0xff, 0xff, 0xff, 0xff, // reserved (non-zero for testing)
        ];

        let mut rs = IcmpRouterSolicitation::new(&mut data[..]).unwrap();
        rs.reserved_mut().set(0);

        // Verify it's now zero
        assert_eq!(&rs.as_ref()[4..8], &[0x00, 0x00, 0x00, 0x00]);
    }
}
