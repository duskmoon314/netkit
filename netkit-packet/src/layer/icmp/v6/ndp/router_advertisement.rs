//! ICMPv6 Router Advertisement message (NDP).

use crate::{field_spec, prelude::*};

field_spec!(CurHopLimitSpec, u8, u8);
field_spec!(FlagsSpec, u8, u8);
field_spec!(RouterLifetimeSpec, u16, u16);
field_spec!(ReachableTimeSpec, u32, u32);
field_spec!(RetransTimerSpec, u32, u32);

/// ICMPv6 Router Advertisement message (Type 134).
///
/// Routers send Router Advertisements periodically, or in response to
/// Router Solicitations, to advertise their presence along with various
/// link and Internet parameters.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Reachable Time                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Retrans Timer                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// **Type**: 134
/// **Code**: 0
///
/// **Flags**:
/// - M (Managed Address Configuration): When set, hosts use managed address
///   configuration (e.g., DHCPv6) to obtain addresses
/// - O (Other Configuration): When set, hosts use DHCPv6 to obtain other
///   configuration information
///
/// **Router Lifetime**: Lifetime (in seconds) associated with the default router
///
/// **Reachable Time**: Time (in milliseconds) that a node assumes a neighbor is
/// reachable after receiving a reachability confirmation
///
/// **Retrans Timer**: Time (in milliseconds) between retransmitted Neighbor
/// Solicitation messages
///
/// Defined in RFC 4861 Section 4.2.
pub struct RouterAdvertisement<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> RouterAdvertisement<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length (without options).
    pub const MIN_LENGTH: usize = 16;

    /// Field range for current hop limit.
    pub const FIELD_CUR_HOP_LIMIT: core::ops::Range<usize> = 4..5;
    /// Field range for flags (M, O, Reserved).
    pub const FIELD_FLAGS: core::ops::Range<usize> = 5..6;
    /// Field range for router lifetime.
    pub const FIELD_ROUTER_LIFETIME: core::ops::Range<usize> = 6..8;
    /// Field range for reachable time.
    pub const FIELD_REACHABLE_TIME: core::ops::Range<usize> = 8..12;
    /// Field range for retrans timer.
    pub const FIELD_RETRANS_TIMER: core::ops::Range<usize> = 12..16;
    /// Field range for options.
    pub const FIELD_OPTIONS: core::ops::RangeFrom<usize> = 16..;

    /// Create from ICMPv6 packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 16 bytes.
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

    /// Get the current hop limit.
    #[inline]
    pub fn cur_hop_limit(&self) -> FieldRef<'_, CurHopLimitSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_CUR_HOP_LIMIT])
    }

    /// Get the flags field.
    #[inline]
    pub fn flags(&self) -> FieldRef<'_, FlagsSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_FLAGS])
    }

    /// Check if the Managed Address Configuration flag (M) is set.
    #[inline]
    pub fn managed_addr_config(&self) -> bool {
        self.flags().get() & 0x80 != 0
    }

    /// Check if the Other Configuration flag (O) is set.
    #[inline]
    pub fn other_config(&self) -> bool {
        self.flags().get() & 0x40 != 0
    }

    /// Get the router lifetime (in seconds).
    #[inline]
    pub fn router_lifetime(&self) -> FieldRef<'_, RouterLifetimeSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_ROUTER_LIFETIME])
    }

    /// Get the reachable time (in milliseconds).
    #[inline]
    pub fn reachable_time(&self) -> FieldRef<'_, ReachableTimeSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_REACHABLE_TIME])
    }

    /// Get the retrans timer (in milliseconds).
    #[inline]
    pub fn retrans_timer(&self) -> FieldRef<'_, RetransTimerSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_RETRANS_TIMER])
    }

    /// Get the options field (NDP options).
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_OPTIONS]
    }
}

impl<T> RouterAdvertisement<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to current hop limit.
    #[inline]
    pub fn cur_hop_limit_mut(&mut self) -> FieldMut<'_, CurHopLimitSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_CUR_HOP_LIMIT])
    }

    /// Get mutable access to flags.
    #[inline]
    pub fn flags_mut(&mut self) -> FieldMut<'_, FlagsSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get mutable access to router lifetime.
    #[inline]
    pub fn router_lifetime_mut(&mut self) -> FieldMut<'_, RouterLifetimeSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_ROUTER_LIFETIME])
    }

    /// Get mutable access to reachable time.
    #[inline]
    pub fn reachable_time_mut(&mut self) -> FieldMut<'_, ReachableTimeSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_REACHABLE_TIME])
    }

    /// Get mutable access to retrans timer.
    #[inline]
    pub fn retrans_timer_mut(&mut self) -> FieldMut<'_, RetransTimerSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_RETRANS_TIMER])
    }

    /// Get mutable access to options field.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_OPTIONS]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for RouterAdvertisement<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for RouterAdvertisement<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_advertisement_parse() {
        let data = vec![
            0x86, 0x00, // type=134, code=0
            0x00, 0x00, // checksum
            64,   // cur hop limit
            0x00, // flags (M=0, O=0)
            0x00, 0x3c, // router lifetime = 60 seconds
            0x00, 0x00, 0x00, 0x00, // reachable time
            0x00, 0x00, 0x00, 0x00, // retrans timer
        ];

        let msg = RouterAdvertisement::new(&data[..]).unwrap();
        assert_eq!(msg.cur_hop_limit().get(), 64);
        assert_eq!(msg.router_lifetime().get(), 60);
        assert!(!msg.managed_addr_config());
        assert!(!msg.other_config());
    }

    #[test]
    fn test_router_advertisement_flags() {
        let data = vec![
            0x86, 0x00, // type=134, code=0
            0x00, 0x00, // checksum
            64,   // cur hop limit
            0xC0, // flags (M=1, O=1)
            0x00, 0x3c, // router lifetime
            0x00, 0x00, 0x00, 0x00, // reachable time
            0x00, 0x00, 0x00, 0x00, // retrans timer
        ];

        let msg = RouterAdvertisement::new(&data[..]).unwrap();
        assert!(msg.managed_addr_config());
        assert!(msg.other_config());
    }
}
