//! ICMPv6 Router Solicitation message (NDP).

use crate::{field_spec, prelude::*};

field_spec!(ReservedSpec, u32, u32);

/// ICMPv6 Router Solicitation message (Type 133).
///
/// Hosts send Router Solicitations to request routers to generate Router
/// Advertisements immediately rather than waiting for the next scheduled time.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Reserved                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// **Type**: 133
/// **Code**: 0
///
/// **Options**: Possible options include Source Link-Layer Address.
///
/// Defined in RFC 4861 Section 4.1.
pub struct RouterSolicitation<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> RouterSolicitation<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length (without options).
    pub const MIN_LENGTH: usize = 8;

    /// Field range for reserved field.
    pub const FIELD_RESERVED: core::ops::Range<usize> = 4..8;
    /// Field range for options.
    pub const FIELD_OPTIONS: core::ops::RangeFrom<usize> = 8..;

    /// Create from ICMPv6 packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 8 bytes.
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

    /// Get the options field (NDP options).
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_OPTIONS]
    }
}

impl<T> RouterSolicitation<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to the reserved field.
    #[inline]
    pub fn reserved_mut(&mut self) -> FieldMut<'_, ReservedSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_RESERVED])
    }

    /// Get mutable access to options field.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_OPTIONS]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for RouterSolicitation<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for RouterSolicitation<T> {
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
            0x85, 0x00, // type=133, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00,
            0x00, // reserved
                  // Options would follow (e.g., source link-layer address)
        ];

        let msg = RouterSolicitation::new(&data[..]).unwrap();
        assert_eq!(msg.options().len(), 0);
    }

    #[test]
    fn test_router_solicitation_with_options() {
        let data = vec![
            0x85, 0x00, // type=133, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // reserved
            0x01, 0x01, // option type=1 (source link-layer), length=1
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // MAC address
        ];

        let msg = RouterSolicitation::new(&data[..]).unwrap();
        assert_eq!(msg.options().len(), 8);
    }
}
