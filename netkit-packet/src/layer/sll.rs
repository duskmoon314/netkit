//! Linux cooked-mode capture (SLL) layer

use crate::field_spec;
use crate::layer::eth::EthType;
use crate::layer::ip::v4::Ipv4;
use crate::utils::{FieldMut, FieldRef, layer_impl};

pub mod arphrd_type;
pub use arphrd_type::ArphrdType;

pub mod packet_type;
pub use packet_type::PacketType;

/// Error type for SLL layer.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum SllError {
    /// Invalid SLL length.
    #[error("Invalid SLL length: Length {0} is less than minimum 16")]
    InvalidLength(usize),
}

field_spec!(PacketTypeSpec, PacketType, u16);
field_spec!(ArphrdTypeSpec, ArphrdType, u16);
field_spec!(LinkLayerAddrLenSpec, u16, u16);
field_spec!(LinkLayerAddrSpec, [u8; 8], u64);
field_spec!(ProtocolTypeSpec, EthType, u16);

/// Minimum length of an SLL header.
pub const MIN_HEADER_LENGTH: usize = 16;

/// Linux Cooked-Mode Capture (SLL) Layer
///
/// ## Packet Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Packet Type           |        ARPHRD Type            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Link-layer Address Length|                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                   Link-layer Address                          |
/// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               |        Protocol Type          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Payload                            |
/// ~                              ...                              ~
/// ```
///
/// - **Packet Type**: 16 bits - Packet direction and type
///   - 0 = Packet sent to us by someone else
///   - 1 = Packet broadcast by someone else
///   - 2 = Packet multicast by someone else
///   - 3 = Packet sent to someone else by someone else
///   - 4 = Packet sent by us
/// - **ARPHRD Type**: 16 bits - Link-layer device type (from Linux's if_arp.h)
///   - 1 = Ethernet (10 or 100Mbps)
///   - 512 = PPP
///   - 772 = Loopback
/// - **Link-layer Address Length**: 16 bits - Length of link-layer address (max 8 bytes)
/// - **Link-layer Address**: 64 bits - Link-layer address (e.g., MAC address), padded to 8 bytes
/// - **Protocol Type**: 16 bits - Protocol type (same as Ethernet EtherType: IPv4=0x0800, IPv6=0x86DD, etc.)
/// - **Payload**: Variable - Upper layer protocol data
///
/// **Note**: SLL is used by libpcap/tcpdump when capturing on the Linux "any" device or
/// other interfaces that don't have a standard link-layer header format.
pub struct Sll<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Sll<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the packet type: 0..2
    pub const FIELD_PACKET_TYPE: core::ops::Range<usize> = 0..2;
    /// Field range of the ARPHRD type: 2..4
    pub const FIELD_ARPHRD_TYPE: core::ops::Range<usize> = 2..4;
    /// Field range of the link-layer address length: 4..6
    pub const FIELD_LL_ADDR_LEN: core::ops::Range<usize> = 4..6;
    /// Field range of the link-layer address: 6..14
    pub const FIELD_LL_ADDR: core::ops::Range<usize> = 6..14;
    /// Field range of the protocol type: 14..16
    pub const FIELD_PROTOCOL_TYPE: core::ops::Range<usize> = 14..16;
    /// Field range of the payload: 16..
    pub const FIELD_PAYLOAD: core::ops::RangeFrom<usize> = 16..;

    /// Create a new SLL layer from raw data without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid SLL packet.
    ///
    /// The data must be at least 16 bytes long. Otherwise, the following
    /// methods may panic when accessing the fields.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the SLL layer.
    pub fn validate(&self) -> Result<(), SllError> {
        if self.data.as_ref().len() < MIN_HEADER_LENGTH {
            return Err(SllError::InvalidLength(self.data.as_ref().len()));
        }

        Ok(())
    }

    /// Create a new SLL layer from raw data.
    #[inline]
    pub fn new(data: T) -> Result<Self, SllError> {
        let res = unsafe { Self::new_unchecked(data) };
        res.validate()?;
        Ok(res)
    }

    /// Get the inner raw data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the packet type.
    #[inline]
    pub fn packet_type(&self) -> FieldRef<'_, PacketTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PACKET_TYPE])
    }

    /// Get the accessor of the ARPHRD type.
    #[inline]
    pub fn arphrd_type(&self) -> FieldRef<'_, ArphrdTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ARPHRD_TYPE])
    }

    /// Get the accessor of the link-layer address length.
    #[inline]
    pub fn ll_addr_len(&self) -> FieldRef<'_, LinkLayerAddrLenSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_LL_ADDR_LEN])
    }

    /// Get the accessor of the link-layer address (8 bytes, padded).
    #[inline]
    pub fn ll_addr(&self) -> FieldRef<'_, LinkLayerAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_LL_ADDR])
    }

    /// Get the accessor of the protocol type.
    #[inline]
    pub fn protocol_type(&self) -> FieldRef<'_, ProtocolTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PROTOCOL_TYPE])
    }

    /// Get the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_PAYLOAD]
    }

    /// Get the IPv4 layer if the protocol type is IPv4.
    pub fn ipv4(&self) -> Option<Ipv4<&[u8]>> {
        if self.protocol_type().get() == EthType::Ipv4 {
            Ipv4::new(self.payload()).ok()
        } else {
            None
        }
    }
}

impl<T> Sll<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the packet type.
    #[inline]
    pub fn packet_type_mut(&mut self) -> FieldMut<'_, PacketTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PACKET_TYPE])
    }

    /// Get the mutable accessor of the ARPHRD type.
    #[inline]
    pub fn arphrd_type_mut(&mut self) -> FieldMut<'_, ArphrdTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ARPHRD_TYPE])
    }

    /// Get the mutable accessor of the link-layer address length.
    #[inline]
    pub fn ll_addr_len_mut(&mut self) -> FieldMut<'_, LinkLayerAddrLenSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_LL_ADDR_LEN])
    }

    /// Get the mutable accessor of the link-layer address.
    #[inline]
    pub fn ll_addr_mut(&mut self) -> FieldMut<'_, LinkLayerAddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_LL_ADDR])
    }

    /// Get the mutable accessor of the protocol type.
    #[inline]
    pub fn protocol_type_mut(&mut self) -> FieldMut<'_, ProtocolTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PROTOCOL_TYPE])
    }

    /// Get the mutable payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_PAYLOAD]
    }

    /// Get the mutable IPv4 layer if the protocol type is IPv4.
    pub fn ipv4_mut(&mut self) -> Option<Ipv4<&mut [u8]>> {
        if self.protocol_type().get() == EthType::Ipv4 {
            Ipv4::new(self.payload_mut()).ok()
        } else {
            None
        }
    }
}

layer_impl!(Sll);

impl<T> core::fmt::Debug for Sll<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Sll");

        let ll_addr = self.ll_addr().get();
        let ll_addr_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            ll_addr[0],
            ll_addr[1],
            ll_addr[2],
            ll_addr[3],
            ll_addr[4],
            ll_addr[5],
            ll_addr[6],
            ll_addr[7]
        );

        f.field("packet_type", &self.packet_type().get())
            .field("arphrd_type", &self.arphrd_type().get())
            .field("ll_addr_len", &self.ll_addr_len().get())
            .field("ll_addr", &ll_addr_str)
            .field("protocol_type", &self.protocol_type().get());

        f.finish()
    }
}

/// Builder for [`Sll`].
#[derive(Clone, Debug, Default)]
pub struct SllBuilder {
    packet_type: Option<PacketType>,
    arphrd_type: Option<u16>,
    ll_addr_len: Option<u16>,
    ll_addr: Option<[u8; 8]>,
    protocol_type: Option<EthType>,
    payload: Vec<u8>,
}

impl SllBuilder {
    /// Create a new SLL builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the packet type.
    pub fn packet_type(&mut self, packet_type: impl Into<PacketType>) -> &mut Self {
        self.packet_type = Some(packet_type.into());
        self
    }

    /// Set the ARPHRD type.
    pub fn arphrd_type(&mut self, arphrd_type: impl Into<u16>) -> &mut Self {
        self.arphrd_type = Some(arphrd_type.into());
        self
    }

    /// Set the link-layer address length.
    pub fn ll_addr_len(&mut self, ll_addr_len: impl Into<u16>) -> &mut Self {
        self.ll_addr_len = Some(ll_addr_len.into());
        self
    }

    /// Set the link-layer address.
    pub fn ll_addr(&mut self, ll_addr: impl Into<[u8; 8]>) -> &mut Self {
        self.ll_addr = Some(ll_addr.into());
        self
    }

    /// Set the protocol type.
    pub fn protocol_type(&mut self, protocol_type: impl Into<EthType>) -> &mut Self {
        self.protocol_type = Some(protocol_type.into());
        self
    }

    /// Set the payload.
    pub fn payload<P: AsRef<[u8]>>(&mut self, payload: P) -> &mut Self {
        self.payload.extend_from_slice(payload.as_ref());
        self
    }

    /// Build the SLL layer.
    pub fn build(&self) -> Sll<Vec<u8>> {
        let len = MIN_HEADER_LENGTH + self.payload.len();

        let mut sll = unsafe { Sll::new_unchecked(vec![0; len]) };

        sll.packet_type_mut()
            .set(self.packet_type.unwrap_or(PacketType::SentToUs));
        sll.arphrd_type_mut()
            .set(ArphrdType::from(self.arphrd_type.unwrap_or(1))); // 1 = ARPHRD_ETHER
        sll.ll_addr_len_mut().set(self.ll_addr_len.unwrap_or(0));
        sll.ll_addr_mut().set(self.ll_addr.unwrap_or([0; 8]));
        sll.protocol_type_mut()
            .set(self.protocol_type.unwrap_or_default());
        sll.payload_mut().copy_from_slice(self.payload.as_ref());

        sll
    }
}

/// Create an SLL layer with the given fields.
///
/// # Example
///
/// ```
/// # use netkit_packet::prelude::*;
/// let sll = sll!(
///     packet_type: PacketType::SentToUs,
///     arphrd_type: 1u16,
///     ll_addr_len: 6u16,
///     ll_addr: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00],
///     protocol_type: EthType::Ipv4,
///     payload: [0x45, 0x00]
/// );
///
/// assert_eq!(sll.packet_type().get(), PacketType::SentToUs);
/// assert_eq!(sll.arphrd_type().get(), ArphrdType::Ether);
/// assert_eq!(sll.protocol_type().get(), EthType::Ipv4);
/// ```
#[macro_export]
macro_rules! sll {
    ($($field : ident : $value : expr),* $(,)? ) => {
        $crate::layer::sll::SllBuilder::new()
            $(.$field($value))*
            .build()
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::eth::EthType;

    #[test]
    fn sll_new_unchecked() {
        let data: [u8; 16] = [
            0x00, 0x00, // packet type: sent to us
            0x00, 0x01, // arphrd type: ether
            0x00, 0x06, // ll addr len: 6
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, // ll addr
            0x08, 0x00, // protocol type: IPv4
        ];

        let sll = unsafe { Sll::new_unchecked(data) };

        assert_eq!(sll.packet_type().get(), PacketType::SentToUs);
        assert_eq!(sll.arphrd_type().get(), ArphrdType::Ether);
        assert_eq!(sll.ll_addr_len().get(), 6);
        assert_eq!(sll.protocol_type().get(), EthType::Ipv4);
        assert_eq!(sll.payload().len(), 0);
    }

    #[test]
    fn sll_new() {
        let data: [u8; 16] = [
            0x00, 0x04, // packet type: sent by us
            0x00, 0x01, // arphrd type: ether
            0x00, 0x06, // ll addr len: 6
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00, // ll addr
            0x08, 0x00, // protocol type: IPv4
        ];

        let sll = Sll::new(data).unwrap();

        assert_eq!(sll.packet_type().get(), PacketType::SentByUs);
        assert_eq!(sll.arphrd_type().get(), ArphrdType::Ether);
        assert_eq!(sll.ll_addr_len().get(), 6);
        assert_eq!(sll.protocol_type().get(), EthType::Ipv4);
    }

    #[test]
    fn sll_macro() {
        let sll = sll!(
            packet_type: PacketType::Broadcast,
            arphrd_type: 1u16,
            ll_addr_len: 6u16,
            ll_addr: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00],
            protocol_type: EthType::Ipv4,
            payload: [0x45, 0x00, 0x00, 0x14]
        );

        assert_eq!(sll.packet_type().get(), PacketType::Broadcast);
        assert_eq!(sll.arphrd_type().get(), ArphrdType::Ether);
        assert_eq!(sll.ll_addr_len().get(), 6);
        assert_eq!(sll.protocol_type().get(), EthType::Ipv4);
        assert_eq!(sll.payload(), &[0x45, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn sll_set_fields() {
        let data: Vec<u8> = vec![0; 16];

        let mut sll = unsafe { Sll::new_unchecked(data) };

        sll.packet_type_mut().set(PacketType::Multicast);
        sll.arphrd_type_mut().set(ArphrdType::Loopback);
        sll.ll_addr_len_mut().set(6);
        sll.ll_addr_mut()
            .set([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x00, 0x00]);
        sll.protocol_type_mut().set(EthType::Ipv6);

        assert_eq!(sll.packet_type().get(), PacketType::Multicast);
        assert_eq!(sll.arphrd_type().get(), ArphrdType::Loopback);
        assert_eq!(sll.ll_addr_len().get(), 6);
        assert_eq!(sll.protocol_type().get(), EthType::Ipv6);
    }

    #[test]
    fn sll_debug() {
        let sll = sll!(
            packet_type: PacketType::SentToUs,
            arphrd_type: 1u16,
            ll_addr_len: 6u16,
            ll_addr: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00],
            protocol_type: EthType::Ipv4
        );

        let debug_str = format!("{:?}", sll);
        assert!(debug_str.contains("Sll"));
        assert!(debug_str.contains("packet_type"));
        assert!(debug_str.contains("SentToUs"));
    }

    #[test]
    fn sll_invalid_length() {
        let data: [u8; 10] = [0; 10];
        let result = Sll::new(data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SllError::InvalidLength(10));
    }

    #[test]
    fn sll_arphrd_can() {
        let data: [u8; 16] = [
            0x00, 0x00, // packet type: sent to us
            0x01, 0x18, // arphrd type: CAN (280 = 0x0118)
            0x00, 0x00, // ll addr len: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ll addr
            0x00, 0x00, // protocol type: ignored for CAN
        ];

        let sll = unsafe { Sll::new_unchecked(data) };

        assert_eq!(sll.arphrd_type().get(), ArphrdType::Can);
    }

    #[test]
    fn sll_arphrd_ieee802() {
        let data: [u8; 16] = [
            0x00, 0x00, // packet type: sent to us
            0x00, 0x06, // arphrd type: IEEE802 (6)
            0x00, 0x06, // ll addr len: 6
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, // ll addr
            0x00, 0x00, // protocol type
        ];

        let sll = unsafe { Sll::new_unchecked(data) };

        assert_eq!(sll.arphrd_type().get(), ArphrdType::Ieee802);
    }

    #[test]
    fn sll_arphrd_loopback() {
        let data: [u8; 16] = [
            0x00, 0x00, // packet type: sent to us
            0x03, 0x04, // arphrd type: Loopback (772 = 0x0304)
            0x00, 0x00, // ll addr len: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ll addr
            0x08, 0x00, // protocol type: IPv4
        ];

        let sll = unsafe { Sll::new_unchecked(data) };

        assert_eq!(sll.arphrd_type().get(), ArphrdType::Loopback);
        assert_eq!(sll.protocol_type().get(), EthType::Ipv4);
        assert!(sll.ipv4().is_none()); // No payload
    }

    #[test]
    fn sll_protocol_type_ipv6() {
        let sll = sll!(
            packet_type: PacketType::SentToUs,
            arphrd_type: 1u16,
            protocol_type: EthType::Ipv6,
        );

        assert_eq!(sll.protocol_type().get(), EthType::Ipv6);
    }

    #[test]
    fn sll_protocol_type_arp() {
        let sll = sll!(
            packet_type: PacketType::SentToUs,
            arphrd_type: 1u16,
            protocol_type: EthType::Arp,
        );

        assert_eq!(sll.protocol_type().get(), EthType::Arp);
    }
}
