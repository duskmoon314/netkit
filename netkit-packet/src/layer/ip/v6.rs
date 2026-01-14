//! IPv6 layer.

use core::net::Ipv6Addr;

use super::IpProtocol;
use crate::{field_spec, impl_target, layer::ip::flow_id::FlowId, prelude::*};

/// Error type for Ipv6.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum Ipv6Error {
    /// Invalid Ipv6 length.
    #[error("Invalid Ipv6 length: Length {0} is less than minimum 40")]
    InvalidLength(usize),

    /// Invalid version.
    #[error("Invalid version: Expected 6, got {0}")]
    InvalidVersion(u8),

    /// Invalid payload length.
    #[error("Invalid payload length: {0}")]
    InvalidPayloadLength(String),

    /// Invalid Arguments.
    #[error("Invalid Arguments: {0}")]
    InvalidArguments(String),
}

impl_target!(frominto, core::net::Ipv6Addr, u128);

field_spec!(VersionSpec6, u8, u8, 0xF0, 4);
field_spec!(TrafficClassSpec, u8, u8);
field_spec!(FlowLabelSpec, u32, u32, 0x000F_FFFF);
field_spec!(PayloadLengthSpec, u16, u16);
field_spec!(NextHeaderSpec, IpProtocol, u8);
field_spec!(HopLimitSpec, u8, u8);
field_spec!(Ipv6AddrSpec, core::net::Ipv6Addr, u128);

/// IPv6 (Internet Protocol version 6) Layer
///
/// ## Packet Format (RFC 8200)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version| Traffic Class |           Flow Label                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Payload Length        |  Next Header  |   Hop Limit   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                         Source Address                        +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                      Destination Address                      +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - **Version**: 4 bits - IP version (always 6 for IPv6)
/// - **Traffic Class**: 8 bits - Traffic class for QoS (similar to DSCP in IPv4)
/// - **Flow Label**: 20 bits - Flow label for QoS handling
/// - **Payload Length**: 16 bits - Length of payload (excludes header, max 65,535 bytes)
/// - **Next Header**: 8 bits - Type of next header (same values as IPv4 Protocol field)
/// - **Hop Limit**: 8 bits - Decremented by 1 at each hop (similar to TTL in IPv4)
/// - **Source Address**: 128 bits - Source IPv6 address
/// - **Destination Address**: 128 bits - Destination IPv6 address
///
/// **Note**: Unlike IPv4, IPv6 has a fixed 40-byte header with no options field.
/// Extension headers are used instead via the Next Header field.
pub struct Ipv6<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Ipv6<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the version and traffic class high bits: 0..1
    pub const FIELD_VERSION_TC_HIGH: core::ops::Range<usize> = 0..1;
    /// Field range of the traffic class low bits and flow label: 1..4
    pub const FIELD_TC_LOW_FLOW: core::ops::Range<usize> = 1..4;
    /// Field range of the traffic class: spans bytes 0-1
    pub const FIELD_TRAFFIC_CLASS: core::ops::Range<usize> = 0..2;
    /// Field range of the flow label: spans bytes 1-4
    pub const FIELD_FLOW_LABEL: core::ops::Range<usize> = 1..4;
    /// Field range of the payload length: 4..6
    pub const FIELD_PAYLOAD_LENGTH: core::ops::Range<usize> = 4..6;
    /// Field range of the next header: 6..7
    pub const FIELD_NEXT_HEADER: core::ops::Range<usize> = 6..7;
    /// Field range of the hop limit: 7..8
    pub const FIELD_HOP_LIMIT: core::ops::Range<usize> = 7..8;
    /// Field range of the src: 8..24
    pub const FIELD_SRC: core::ops::Range<usize> = 8..24;
    /// Field range of the dst: 24..40
    pub const FIELD_DST: core::ops::Range<usize> = 24..40;

    /// Minimum header length (IPv6 has fixed header size).
    pub const MIN_HEADER_LENGTH: usize = 40;

    /// Create a new Ipv6 layer without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid Ipv6 packet.
    ///
    /// The data must be at least 40 bytes long. Otherwise, the following
    /// methods may panic when accessing the fields.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the Ipv6 layer.
    pub fn validate(&self) -> Result<(), Ipv6Error> {
        let data = self.data.as_ref();

        // Check minimum length
        if data.len() < Self::MIN_HEADER_LENGTH {
            return Err(Ipv6Error::InvalidLength(data.len()));
        }

        // Check version field
        let version = self.version().get();
        if version != 6 {
            return Err(Ipv6Error::InvalidVersion(version));
        }

        // Check payload length field
        let payload_length = self.payload_length().get() as usize;
        let total_length = Self::MIN_HEADER_LENGTH + payload_length;

        if total_length > data.len() {
            return Err(Ipv6Error::InvalidPayloadLength(format!(
                "Payload length {} requires total {} bytes, but data length is {}",
                payload_length,
                total_length,
                data.len()
            )));
        }

        Ok(())
    }

    /// Create a new Ipv6 layer from raw data.
    #[inline]
    pub fn new(data: T) -> Result<Self, Ipv6Error> {
        let res = unsafe { Self::new_unchecked(data) };
        res.validate()?;
        Ok(res)
    }

    /// Get the inner raw data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the version.
    #[inline]
    pub fn version(&self) -> FieldRef<'_, VersionSpec6> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_VERSION_TC_HIGH])
    }

    /// Get the accessor of the traffic class.
    ///
    /// Traffic class is split across two bytes: 4 bits in byte 0, 4 bits in byte 1.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        let data = self.data.as_ref();
        ((data[0] & 0x0F) << 4) | ((data[1] & 0xF0) >> 4)
    }

    /// Get the accessor of the flow label.
    ///
    /// Flow label is 20 bits spanning bytes 1-4.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        let data = self.data.as_ref();
        let bytes = [0, data[1] & 0x0F, data[2], data[3]];
        u32::from_be_bytes(bytes)
    }

    /// Get the accessor of the payload length.
    #[inline]
    pub fn payload_length(&self) -> FieldRef<'_, PayloadLengthSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PAYLOAD_LENGTH])
    }

    /// Get the accessor of the next header.
    #[inline]
    pub fn next_header(&self) -> FieldRef<'_, NextHeaderSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the accessor of the hop limit.
    #[inline]
    pub fn hop_limit(&self) -> FieldRef<'_, HopLimitSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_HOP_LIMIT])
    }

    /// Get the accessor of the src ip address.
    #[inline]
    pub fn src(&self) -> FieldRef<'_, Ipv6AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SRC])
    }

    /// Get the accessor of the dst ip address.
    #[inline]
    pub fn dst(&self) -> FieldRef<'_, Ipv6AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DST])
    }

    /// Get the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[Self::MIN_HEADER_LENGTH..]
    }

    /// Get the TCP layer if the next header is TCP.
    #[inline]
    pub fn tcp(&self) -> Option<Tcp<&[u8]>> {
        if self.next_header().get() == IpProtocol::Tcp {
            Tcp::new(self.payload()).ok()
        } else {
            None
        }
    }

    /// Get the UDP layer if the next header is UDP.
    #[inline]
    pub fn udp(&self) -> Option<Udp<&[u8]>> {
        if self.next_header().get() == IpProtocol::Udp {
            Udp::new(self.payload()).ok()
        } else {
            None
        }
    }

    /// Get the ICMPv6 layer if the next header is ICMPv6.
    #[inline]
    pub fn icmpv6(&self) -> Option<Icmpv6<&[u8]>> {
        if self.next_header().get() == IpProtocol::Ipv6Icmp {
            Icmpv6::new(self.payload()).ok()
        } else {
            None
        }
    }

    /// Get the flow id formed by ip, port and protocol.
    ///
    /// # Arguments
    ///
    /// * `elements` - Number of elements to use for the flow id:
    ///   - 1: only ip addresses
    ///   - 2: src/dst ip
    ///   - 3: src/dst ip + protocol
    ///   - 4: src/dst ip + src/dst port
    ///   - 5: src/dst ip + protocol + src/dst port
    /// * `symmetric` - Whether to create a symmetric flow id (i.e., src/dst swapped)
    ///   - true: the smaller ip address is always src
    ///   - false: the src/dst as is
    ///   - If `elements` is 1, then `symmetric` is used to determine which ip address is used.
    ///     - true: the src ip address is used
    ///     - false: the dst ip address is used
    pub fn flow_id(&self, elements: u8, symmetric: bool) -> Result<FlowId, Ipv6Error> {
        match (elements, symmetric) {
            (1, true) => Ok(FlowId::from(self.src().get())),
            (1, false) => Ok(FlowId::from(self.dst().get())),
            (2, sym) => Ok(FlowId::from_tuple2(self.src().get(), self.dst().get(), sym)),
            (3, sym) => Ok(FlowId::from_tuple3(
                self.src().get(),
                self.dst().get(),
                self.next_header().get(),
                sym,
            )),
            (4, sym) => {
                let udp = self.udp();
                let tcp = self.tcp();
                if let Some(udp) = udp {
                    Ok(FlowId::from_tuple4(
                        self.src().get(),
                        self.dst().get(),
                        udp.src_port().get(),
                        udp.dst_port().get(),
                        sym,
                    ))
                } else if let Some(tcp) = tcp {
                    Ok(FlowId::from_tuple4(
                        self.src().get(),
                        self.dst().get(),
                        tcp.src_port().get(),
                        tcp.dst_port().get(),
                        sym,
                    ))
                } else {
                    Err(Ipv6Error::InvalidArguments(
                        "Cannot extract ports from non-TCP/UDP protocol".to_string(),
                    ))
                }
            }
            (5, sym) => {
                let udp = self.udp();
                let tcp = self.tcp();
                if let Some(udp) = udp {
                    Ok(FlowId::from_tuple5(
                        self.src().get(),
                        self.dst().get(),
                        udp.src_port().get(),
                        udp.dst_port().get(),
                        self.next_header().get(),
                        sym,
                    ))
                } else if let Some(tcp) = tcp {
                    Ok(FlowId::from_tuple5(
                        self.src().get(),
                        self.dst().get(),
                        tcp.src_port().get(),
                        tcp.dst_port().get(),
                        self.next_header().get(),
                        sym,
                    ))
                } else {
                    Err(Ipv6Error::InvalidArguments(
                        "Cannot extract ports from non-TCP/UDP protocol".to_string(),
                    ))
                }
            }

            _ => Err(Ipv6Error::InvalidArguments(
                "Elements must be between 1 and 5".to_string(),
            )),
        }
    }
}

impl<T> Ipv6<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Set the version (should always be 6).
    #[inline]
    pub fn version_mut(&mut self) -> FieldMut<'_, VersionSpec6> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_VERSION_TC_HIGH])
    }

    /// Set the traffic class.
    ///
    /// Traffic class is split across two bytes.
    #[inline]
    pub fn set_traffic_class(&mut self, tc: u8) {
        let data = self.data.as_mut();
        data[0] = (data[0] & 0xF0) | ((tc >> 4) & 0x0F);
        data[1] = (data[1] & 0x0F) | ((tc << 4) & 0xF0);
    }

    /// Set the flow label.
    ///
    /// Flow label is 20 bits, only the lower 20 bits of the input are used.
    #[inline]
    pub fn set_flow_label(&mut self, flow: u32) {
        let data = self.data.as_mut();
        let bytes = (flow & 0x000F_FFFF).to_be_bytes();
        data[1] = (data[1] & 0xF0) | (bytes[1] & 0x0F);
        data[2] = bytes[2];
        data[3] = bytes[3];
    }

    /// Get the mutable accessor of the payload length.
    #[inline]
    pub fn payload_length_mut(&mut self) -> FieldMut<'_, PayloadLengthSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PAYLOAD_LENGTH])
    }

    /// Get the mutable accessor of the next header.
    #[inline]
    pub fn next_header_mut(&mut self) -> FieldMut<'_, NextHeaderSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the mutable accessor of the hop limit.
    #[inline]
    pub fn hop_limit_mut(&mut self) -> FieldMut<'_, HopLimitSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_HOP_LIMIT])
    }

    /// Get the mutable accessor of the src ip address.
    #[inline]
    pub fn src_mut(&mut self) -> FieldMut<'_, Ipv6AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SRC])
    }

    /// Get the mutable accessor of the dst ip address.
    #[inline]
    pub fn dst_mut(&mut self) -> FieldMut<'_, Ipv6AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DST])
    }

    /// Get the mutable payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::MIN_HEADER_LENGTH..]
    }
}

layer_impl!(Ipv6);

/// Builder for [`Ipv6`].
#[derive(Clone, Debug, Default)]
pub struct Ipv6Builder {
    traffic_class: Option<u8>,
    flow_label: Option<u32>,
    payload_length: Option<u16>,
    next_header: Option<IpProtocol>,
    hop_limit: Option<u8>,
    src: Option<Ipv6Addr>,
    dst: Option<Ipv6Addr>,
    payload: Vec<u8>,
}

impl Ipv6Builder {
    /// Create a new Ipv6 builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the traffic class.
    pub fn traffic_class(&mut self, tc: impl Into<u8>) -> &mut Self {
        self.traffic_class = Some(tc.into());
        self
    }

    /// Set the flow label.
    pub fn flow_label(&mut self, flow: impl Into<u32>) -> &mut Self {
        self.flow_label = Some(flow.into() & 0x000F_FFFF);
        self
    }

    /// Set the payload length.
    pub fn payload_length(&mut self, len: impl Into<u16>) -> &mut Self {
        self.payload_length = Some(len.into());
        self
    }

    /// Set the next header.
    pub fn next_header(&mut self, nh: IpProtocol) -> &mut Self {
        self.next_header = Some(nh);
        self
    }

    /// Set the hop limit.
    pub fn hop_limit(&mut self, hl: impl Into<u8>) -> &mut Self {
        self.hop_limit = Some(hl.into());
        self
    }

    /// Set the src ip address.
    pub fn src(&mut self, src: Ipv6Addr) -> &mut Self {
        self.src = Some(src);
        self
    }

    /// Set the dst ip address.
    pub fn dst(&mut self, dst: Ipv6Addr) -> &mut Self {
        self.dst = Some(dst);
        self
    }

    /// Set the payload.
    pub fn payload<T: AsRef<[u8]>>(&mut self, payload: T) -> &mut Self {
        self.payload.extend_from_slice(payload.as_ref());
        self
    }

    /// Build the Ipv6 layer.
    pub fn build(&self) -> Ipv6<Vec<u8>> {
        let payload_length = self.payload_length.unwrap_or(self.payload.len() as u16);

        let total_length = Ipv6::<Vec<u8>>::MIN_HEADER_LENGTH + payload_length as usize;

        let mut ipv6 = unsafe { Ipv6::new_unchecked(vec![0; total_length]) };

        ipv6.version_mut().set(6);
        ipv6.set_traffic_class(self.traffic_class.unwrap_or(0));
        ipv6.set_flow_label(self.flow_label.unwrap_or(0));
        ipv6.payload_length_mut().set(payload_length);
        ipv6.next_header_mut()
            .set(self.next_header.unwrap_or(IpProtocol::Reserved(255)));
        ipv6.hop_limit_mut().set(self.hop_limit.unwrap_or(64));
        ipv6.src_mut()
            .set(self.src.unwrap_or(Ipv6Addr::UNSPECIFIED));
        ipv6.dst_mut()
            .set(self.dst.unwrap_or(Ipv6Addr::UNSPECIFIED));
        ipv6.payload_mut().copy_from_slice(self.payload.as_ref());

        ipv6
    }
}

/// Create an Ipv6 layer with the given fields.
///
/// # Example
///
/// ```
/// # use netkit_packet::prelude::*;
/// # use std::net::Ipv6Addr;
/// let ipv6 = ipv6!(
///     src: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
///     dst: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
///     next_header: IpProtocol::Udp,
///     payload: [1, 2, 3, 4],
/// );
///
/// assert_eq!(ipv6.version().get(), 6);
/// assert_eq!(ipv6.payload_length().get(), 4);
/// assert_eq!(ipv6.src().get(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
/// assert_eq!(ipv6.dst().get(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
/// assert_eq!(ipv6.next_header().get(), IpProtocol::Udp);
/// assert_eq!(ipv6.payload(), &[1, 2, 3, 4]);
/// ```
#[macro_export]
macro_rules! ipv6 {
    ($($field : ident : $value : expr),* $(,)?) => {
        $crate::layer::ip::v6::Ipv6Builder::new()
            $(.$field($value))*
            .build()
    };
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use core::net::Ipv6Addr;

    #[test]
    fn ipv6_new_unchecked() {
        let data: [u8; 52] = [
            0x60, 0x00, 0x00, 0x00, // version 6, tc 0, flow 0
            0x00, 0x0c, // payload length 12 (8 UDP header + 4 payload)
            0x11, // next header: UDP
            0x40, // hop limit: 64
            // src: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // dst: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, // UDP header + payload
            0x04, 0xd2, 0x04, 0xd3, // src port 1234, dst port 1235
            0x00, 0x0c, // length 12
            0x00, 0x00, // checksum 0
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let ipv6 = unsafe { Ipv6::new_unchecked(data) };

        assert_eq!(ipv6.version().get(), 6);
        assert_eq!(ipv6.traffic_class(), 0);
        assert_eq!(ipv6.flow_label(), 0);
        assert_eq!(ipv6.payload_length().get(), 12);
        assert_eq!(ipv6.next_header().get(), IpProtocol::Udp);
        assert_eq!(ipv6.hop_limit().get(), 64);
        assert_eq!(
            ipv6.src().get(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            ipv6.dst().get(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
        );
    }

    #[test]
    fn ipv6_macro() {
        let ipv6 = ipv6!(
            src: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            dst: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Udp,
            payload: vec![1, 2, 3, 4],
        );

        assert_eq!(ipv6.version().get(), 6);
        assert_eq!(ipv6.payload_length().get(), 4);
        assert_eq!(
            ipv6.src().get(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            ipv6.dst().get(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
        );
        assert_eq!(ipv6.next_header().get(), IpProtocol::Udp);
        assert_eq!(ipv6.payload(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_validate_invalid_length() {
        let data = [0u8; 30]; // Too short
        let result = Ipv6::new(&data[..]);
        assert!(matches!(result, Err(Ipv6Error::InvalidLength(30))));
    }

    #[test]
    fn test_validate_invalid_version() {
        let mut data = [0u8; 40];
        data[0] = 0x40; // version 4
        let ipv6 = unsafe { Ipv6::new_unchecked(&data[..]) };
        let result = ipv6.validate();
        assert!(matches!(result, Err(Ipv6Error::InvalidVersion(4))));
    }

    #[test]
    fn test_validate_invalid_payload_length() {
        let mut data = [0u8; 40];
        data[0] = 0x60; // version 6
        data[4] = 0x00; // payload_length = 100 (exceeds data)
        data[5] = 0x64;
        let ipv6 = unsafe { Ipv6::new_unchecked(&data[..]) };
        let result = ipv6.validate();
        assert!(matches!(result, Err(Ipv6Error::InvalidPayloadLength(_))));
    }

    #[test]
    fn test_validate_success() {
        let mut data = [0u8; 40];
        data[0] = 0x60; // version 6
        data[4] = 0x00; // payload_length = 0
        data[5] = 0x00;
        let result = Ipv6::new(&data[..]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_traffic_class() {
        let mut data = vec![0u8; 40];
        data[0] = 0x60; // version 6, TC high nibble = 0

        let mut ipv6 = Ipv6::new(&mut data[..]).unwrap();

        ipv6.set_traffic_class(0xAB);
        assert_eq!(ipv6.traffic_class(), 0xAB);
        assert_eq!(ipv6.version().get(), 6); // Version should still be 6
    }

    #[test]
    fn test_flow_label() {
        let mut data = vec![0u8; 40];
        data[0] = 0x60; // version 6

        let mut ipv6 = Ipv6::new(&mut data[..]).unwrap();

        ipv6.set_flow_label(0x12345);
        assert_eq!(ipv6.flow_label(), 0x12345);

        // Test that only 20 bits are used
        ipv6.set_flow_label(0xFFFFFFFF);
        assert_eq!(ipv6.flow_label(), 0x000FFFFF);
    }

    #[test]
    fn ipv6_tcp() {
        let data: [u8; 60] = [
            0x60, 0x00, 0x00, 0x00, // version 6, tc 0, flow 0
            0x00, 0x14, // payload length 20 (TCP header)
            0x06, // next header: TCP
            0x40, // hop limit: 64
            // src: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // dst: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, // TCP header (minimal)
            0x04, 0xd2, // src port 1234
            0x00, 0x50, // dst port 80
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // data offset 5, flags
            0x20, 0x00, // window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent ptr
        ];

        let ipv6 = Ipv6::new(data).unwrap();
        let tcp = ipv6.tcp().unwrap();

        assert_eq!(tcp.src_port().get(), 1234);
        assert_eq!(tcp.dst_port().get(), 80);
    }
}
