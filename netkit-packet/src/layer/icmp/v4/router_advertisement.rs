//! ICMPv4 Router Advertisement message.

use crate::{field_spec, prelude::*};
use core::net::Ipv4Addr;

field_spec!(NumAddrsSpec, u8, u8);
field_spec!(AddrEntrySizeSpec, u8, u8);
field_spec!(LifetimeSpec, u16, u16);
field_spec!(RouterAddressSpec, Ipv4Addr, u32);
field_spec!(PreferenceLevelSpec, u32, u32);

/// ICMPv4 Router Advertisement message (Type 9).
///
/// Routers periodically multicast Router Advertisements to advertise their presence,
/// or send them in response to Router Solicitations.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Num Addrs   |Addr Entry Size|           Lifetime            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Router Address[1]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Preference Level[1]                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Router Address[2]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Preference Level[2]                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// ```
///
/// **Type**: 9
/// **Code**: 0
///
/// **Num Addrs**: Number of router addresses advertised in this message
///
/// **Addr Entry Size**: Size in 32-bit words of each Router Address entry.
/// Must be 2 (8 bytes = 4 bytes address + 4 bytes preference).
///
/// **Lifetime**: Maximum time in seconds that the advertisement is valid
///
/// **Router Address**: IPv4 address of the router on this interface
///
/// **Preference Level**: 32-bit preference for this router address (to be interpreted
/// as signed). Higher values indicate more preferable routers.
///
/// Defined in RFC 1256.
pub struct IcmpRouterAdvertisement<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpRouterAdvertisement<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length (without router addresses).
    pub const MIN_LENGTH: usize = 8;

    /// Size of each router address entry (address + preference).
    pub const ROUTER_ENTRY_SIZE: usize = 8;

    /// Field range for number of addresses.
    pub const FIELD_NUM_ADDRS: core::ops::Range<usize> = 4..5;
    /// Field range for address entry size.
    pub const FIELD_ADDR_ENTRY_SIZE: core::ops::Range<usize> = 5..6;
    /// Field range for lifetime.
    pub const FIELD_LIFETIME: core::ops::Range<usize> = 6..8;
    /// Field range for router entries (variable length).
    pub const FIELD_ROUTER_ENTRIES: core::ops::RangeFrom<usize> = 8..;

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
        if data.as_ref().len() < Self::MIN_LENGTH {
            return None;
        }

        let num_addrs = data.as_ref()[4] as usize;
        let addr_entry_size = data.as_ref()[5] as usize;
        let required_len = Self::MIN_LENGTH + (num_addrs * addr_entry_size * 4);

        if data.as_ref().len() >= required_len && addr_entry_size == 2 {
            Some(unsafe { Self::new_unchecked(data) })
        } else {
            None
        }
    }

    /// Get the number of router addresses advertised.
    #[inline]
    pub fn num_addrs(&self) -> FieldRef<'_, NumAddrsSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_NUM_ADDRS])
    }

    /// Get the address entry size (in 32-bit words).
    ///
    /// This should always be 2 (8 bytes per entry).
    #[inline]
    pub fn addr_entry_size(&self) -> FieldRef<'_, AddrEntrySizeSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_ADDR_ENTRY_SIZE])
    }

    /// Get the lifetime (in seconds).
    #[inline]
    pub fn lifetime(&self) -> FieldRef<'_, LifetimeSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_LIFETIME])
    }

    /// Get router entries as a slice.
    #[inline]
    pub fn router_entries(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_ROUTER_ENTRIES]
    }

    /// Get a specific router address by index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[inline]
    pub fn router_address(&self, index: usize) -> Option<FieldRef<'_, RouterAddressSpec>> {
        let num_addrs = self.num_addrs().get() as usize;
        if index >= num_addrs {
            return None;
        }

        let offset = 8 + (index * Self::ROUTER_ENTRY_SIZE);
        if offset + 4 <= self.as_ref().len() {
            Some(FieldRef::new(&self.as_ref()[offset..offset + 4]))
        } else {
            None
        }
    }

    /// Get a specific preference level by index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[inline]
    pub fn preference_level(&self, index: usize) -> Option<FieldRef<'_, PreferenceLevelSpec>> {
        let num_addrs = self.num_addrs().get() as usize;
        if index >= num_addrs {
            return None;
        }

        let offset = 8 + (index * Self::ROUTER_ENTRY_SIZE) + 4;
        if offset + 4 <= self.as_ref().len() {
            Some(FieldRef::new(&self.as_ref()[offset..offset + 4]))
        } else {
            None
        }
    }
}

impl<T> IcmpRouterAdvertisement<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to number of addresses.
    #[inline]
    pub fn num_addrs_mut(&mut self) -> FieldMut<'_, NumAddrsSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_NUM_ADDRS])
    }

    /// Get mutable access to address entry size.
    #[inline]
    pub fn addr_entry_size_mut(&mut self) -> FieldMut<'_, AddrEntrySizeSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_ADDR_ENTRY_SIZE])
    }

    /// Get mutable access to lifetime.
    #[inline]
    pub fn lifetime_mut(&mut self) -> FieldMut<'_, LifetimeSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_LIFETIME])
    }

    /// Get mutable access to router entries.
    #[inline]
    pub fn router_entries_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_ROUTER_ENTRIES]
    }

    /// Get mutable access to a specific router address by index.
    #[inline]
    pub fn router_address_mut(&mut self, index: usize) -> Option<FieldMut<'_, RouterAddressSpec>> {
        let num_addrs = self.num_addrs().get() as usize;
        if index >= num_addrs {
            return None;
        }

        let offset = 8 + (index * Self::ROUTER_ENTRY_SIZE);
        let len = self.as_ref().len();
        if offset + 4 <= len {
            Some(FieldMut::new(&mut self.as_mut()[offset..offset + 4]))
        } else {
            None
        }
    }

    /// Get mutable access to a specific preference level by index.
    #[inline]
    pub fn preference_level_mut(
        &mut self,
        index: usize,
    ) -> Option<FieldMut<'_, PreferenceLevelSpec>> {
        let num_addrs = self.num_addrs().get() as usize;
        if index >= num_addrs {
            return None;
        }

        let offset = 8 + (index * Self::ROUTER_ENTRY_SIZE) + 4;
        let len = self.as_ref().len();
        if offset + 4 <= len {
            Some(FieldMut::new(&mut self.as_mut()[offset..offset + 4]))
        } else {
            None
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for IcmpRouterAdvertisement<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for IcmpRouterAdvertisement<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_advertisement_single() {
        let data = vec![
            0x09, 0x00, // type=9, code=0
            0x00, 0x00, // checksum
            0x01, // num addrs = 1
            0x02, // addr entry size = 2 (8 bytes)
            0x00, 0x78, // lifetime = 120 seconds
            // Router address 1: 192.168.1.1
            192, 168, 1, 1, // Preference level: 100
            0x00, 0x00, 0x00, 0x64,
        ];

        let ra = IcmpRouterAdvertisement::new(&data[..]).unwrap();
        assert_eq!(ra.num_addrs().get(), 1);
        assert_eq!(ra.addr_entry_size().get(), 2);
        assert_eq!(ra.lifetime().get(), 120);
        assert_eq!(
            ra.router_address(0).unwrap().get(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(ra.preference_level(0).unwrap().get(), 100u32);
    }

    #[test]
    fn test_router_advertisement_multiple() {
        let data = vec![
            0x09, 0x00, // type=9, code=0
            0x00, 0x00, // checksum
            0x02, // num addrs = 2
            0x02, // addr entry size = 2
            0x04, 0xb0, // lifetime = 1200 seconds
            // Router address 1: 10.0.0.1
            10, 0, 0, 1, // Preference level: 200
            0x00, 0x00, 0x00, 0xc8, // Router address 2: 10.0.0.2
            10, 0, 0, 2, // Preference level: 100
            0x00, 0x00, 0x00, 0x64,
        ];

        let ra = IcmpRouterAdvertisement::new(&data[..]).unwrap();
        assert_eq!(ra.num_addrs().get(), 2);
        assert_eq!(
            ra.router_address(0).unwrap().get(),
            Ipv4Addr::new(10, 0, 0, 1)
        );
        assert_eq!(ra.preference_level(0).unwrap().get(), 200u32);
        assert_eq!(
            ra.router_address(1).unwrap().get(),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(ra.preference_level(1).unwrap().get(), 100u32);
    }

    #[test]
    fn test_router_advertisement_mutation() {
        let mut data = vec![
            0x09, 0x00, // type=9, code=0
            0x00, 0x00, // checksum
            0x01, // num addrs = 1
            0x02, // addr entry size = 2
            0x00, 0x00, // lifetime
            // Router address
            0, 0, 0, 0, // Preference level
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut ra = IcmpRouterAdvertisement::new(&mut data[..]).unwrap();
        ra.lifetime_mut().set(300);
        ra.router_address_mut(0)
            .unwrap()
            .set(Ipv4Addr::new(172, 16, 0, 1));
        ra.preference_level_mut(0).unwrap().set(150);

        assert_eq!(ra.lifetime().get(), 300);
        assert_eq!(
            ra.router_address(0).unwrap().get(),
            Ipv4Addr::new(172, 16, 0, 1)
        );
        assert_eq!(ra.preference_level(0).unwrap().get(), 150u32);
    }

    #[test]
    fn test_router_advertisement_out_of_bounds() {
        let data = vec![
            0x09, 0x00, // type=9, code=0
            0x00, 0x00, // checksum
            0x01, // num addrs = 1
            0x02, // addr entry size = 2
            0x00, 0x78, // lifetime
            // Router address 1
            192, 168, 1, 1, // Preference level
            0x00, 0x00, 0x00, 0x64,
        ];

        let ra = IcmpRouterAdvertisement::new(&data[..]).unwrap();
        assert!(ra.router_address(0).is_some());
        assert!(ra.router_address(1).is_none()); // Out of bounds
        assert!(ra.preference_level(0).is_some());
        assert!(ra.preference_level(1).is_none()); // Out of bounds
    }
}
