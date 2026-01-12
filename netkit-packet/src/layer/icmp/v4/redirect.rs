//! Redirect message parsing.

use crate::{field_spec, prelude::*};
use std::net::Ipv4Addr;

field_spec!(RedirectGatewaySpec, Ipv4Addr, u32);

/// ICMP Redirect message.
///
/// This message informs a host to use a different gateway for certain
/// destinations. The gateway address field contains the IP address of the
/// gateway to which traffic should be redirected.
pub struct IcmpRedirect<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpRedirect<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of gateway address: 4..8
    pub const FIELD_GATEWAY: core::ops::Range<usize> = 4..8;
    /// Field range of original datagram: 8..
    pub const FIELD_ORIGINAL_DATAGRAM: core::ops::RangeFrom<usize> = 8..;

    /// Minimum length for Redirect message.
    pub const MIN_LENGTH: usize = 8;

    /// Create a new Redirect message.
    ///
    /// Returns `None` if the data is too short.
    pub fn new(data: T) -> Option<Self> {
        if data.as_ref().len() < Self::MIN_LENGTH {
            return None;
        }
        Some(Self { data })
    }

    /// Get the gateway address to which traffic should be redirected.
    #[inline]
    pub fn gateway(&self) -> FieldRef<'_, RedirectGatewaySpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_GATEWAY])
    }

    /// Get the original datagram (IP header + first 8 bytes of data).
    ///
    /// This contains the IP header and the first 8 bytes of the original
    /// datagram's data.
    #[inline]
    pub fn original_datagram(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_ORIGINAL_DATAGRAM]
    }

    /// Try to parse the original IPv4 header.
    #[inline]
    pub fn original_ipv4(&self) -> Option<Ipv4<&[u8]>> {
        Ipv4::new(self.original_datagram()).ok()
    }
}

impl<T> IcmpRedirect<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable gateway address.
    #[inline]
    pub fn gateway_mut(&mut self) -> FieldMut<'_, RedirectGatewaySpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_GATEWAY])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_parse() {
        // Create a minimal Redirect packet
        let mut data = vec![0u8; 36]; // 8 ICMP header + 28 bytes original datagram
        data[0] = 5; // Redirect
        data[1] = 1; // Redirect for host

        // Gateway address: 192.168.1.254
        data[4] = 192;
        data[5] = 168;
        data[6] = 1;
        data[7] = 254;

        // Add some dummy IPv4 header data
        data[8] = 0x45; // Version 4, IHL 5
        data[9] = 0x00; // TOS
        data[10] = 0x00;
        data[11] = 0x1C; // Total length 28

        let icmp = Icmpv4::new(&data[..]).unwrap();
        assert_eq!(icmp.msg_type().get(), Icmpv4Type::Redirect);
        assert_eq!(icmp.code().get(), 1);

        // Access Redirect specific fields
        let redirect = icmp.redirect().unwrap();
        assert_eq!(redirect.gateway().get(), Ipv4Addr::new(192, 168, 1, 254));

        // Verify we can parse the original IPv4 header
        let original_ipv4 = redirect.original_ipv4().unwrap();
        assert_eq!(original_ipv4.version(), 4);
        assert_eq!(original_ipv4.ihl().get(), 5);
    }
}
