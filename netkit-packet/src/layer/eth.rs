//! Ethernet layer.

use crate::{field_spec, prelude::*};

pub mod eth_addr;
pub use eth_addr::*;

pub mod eth_type;
pub use eth_type::*;

/// Error type for Eth layer.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum EthError {
    /// Invalid Eth length.
    #[error("Invalid Eth length: Length {0} is less than minimum 14")]
    InvalidLength(usize),
}

field_spec!(EthAddrSpec, EthAddr, [u8; 6]);
field_spec!(EthTypeSpec, EthType, u16);

/// Minimum length of an Eth header.
pub const MIN_HEADER_LENGTH: usize = 14;

/// Ethernet layer.
pub struct Eth<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Eth<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the destination MAC address: 0..6
    pub const FIELD_DST: core::ops::Range<usize> = 0..6;
    /// Field range of the source MAC address: 6..12
    pub const FIELD_SRC: core::ops::Range<usize> = 6..12;
    /// Field range of the Eth type: 12..14
    pub const FIELD_ETH_TYPE: core::ops::Range<usize> = 12..14;
    /// Field range of the payload: 14..
    pub const FIELD_PAYLOAD: core::ops::RangeFrom<usize> = 14..;

    /// Create a new Eth layer from raw data without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid Eth packet.
    ///
    /// The data must be at least 14 bytes long. Otherwise, the following
    /// methods may panic when accessing the fields.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the Eth layer.
    pub fn validate(&self) -> Result<(), EthError> {
        if self.data.as_ref().len() < MIN_HEADER_LENGTH {
            return Err(EthError::InvalidLength(self.data.as_ref().len()));
        }

        Ok(())
    }

    /// Create a new Eth layer from raw data.
    #[inline]
    pub fn new(data: T) -> Result<Self, EthError> {
        let res = unsafe { Self::new_unchecked(data) };
        res.validate()?;
        Ok(res)
    }

    /// Get the inner raw data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the destination MAC address.
    #[inline]
    pub fn dst(&self) -> &Field<EthAddrSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_DST])
    }

    /// Get the accessor of the source MAC address.
    #[inline]
    pub fn src(&self) -> &Field<EthAddrSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_SRC])
    }

    /// Get the accessor of the Eth type.
    #[inline]
    pub fn eth_type(&self) -> &Field<EthTypeSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_ETH_TYPE])
    }

    /// Get the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_PAYLOAD]
    }

    /// Get the IPv4 layer if the Eth type is IPv4.
    pub fn ipv4(&self) -> Option<Ipv4<&[u8]>> {
        if self.eth_type().get() == EthType::Ipv4 {
            Ipv4::new(self.payload()).ok()
        } else {
            None
        }
    }
}

impl<T> Eth<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the destination MAC address.
    #[inline]
    pub fn dst_mut(&mut self) -> &mut Field<EthAddrSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_DST])
    }

    /// Get the mutable accessor of the source MAC address.
    #[inline]
    pub fn src_mut(&mut self) -> &mut Field<EthAddrSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_SRC])
    }

    /// Get the mutable accessor of the Eth type.
    #[inline]
    pub fn eth_type_mut(&mut self) -> &mut Field<EthTypeSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_ETH_TYPE])
    }

    /// Get the mutable payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_PAYLOAD]
    }

    /// Get the mutable IPv4 layer if the Eth type is IPv4.
    pub fn ipv4_mut(&mut self) -> Option<Ipv4<&mut [u8]>> {
        if self.eth_type().get() == EthType::Ipv4 {
            Ipv4::new(self.payload_mut()).ok()
        } else {
            None
        }
    }
}

layer_impl!(Eth);

impl<T> core::fmt::Debug for Eth<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Eth");

        f.field("dst", &format_args!("{}", self.dst().get()))
            .field("src", &format_args!("{}", self.src().get()))
            .field("eth_type", &self.eth_type().get());

        // TODO: Print payload

        f.finish()
    }
}

/// Builder for [`Eth`].
#[derive(Clone, Debug, Default)]
pub struct EthBuilder {
    src: Option<EthAddr>,
    dst: Option<EthAddr>,
    eth_type: Option<EthType>,
    payload: Vec<u8>,
}

impl EthBuilder {
    /// Create a new Eth builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the source MAC address.
    pub fn src(&mut self, src: impl Into<EthAddr>) -> &mut Self {
        self.src = Some(src.into());
        self
    }

    /// Set the destination MAC address.
    pub fn dst(&mut self, dst: impl Into<EthAddr>) -> &mut Self {
        self.dst = Some(dst.into());
        self
    }

    /// Set the Eth type.
    pub fn eth_type(&mut self, eth_type: impl Into<EthType>) -> &mut Self {
        self.eth_type = Some(eth_type.into());
        self
    }

    /// Set the payload.
    pub fn payload<T: AsRef<[u8]>>(&mut self, payload: T) -> &mut Self {
        self.payload.extend_from_slice(payload.as_ref());
        self
    }

    /// Build the Eth layer.
    pub fn build(&self) -> Eth<Vec<u8>> {
        let len = MIN_HEADER_LENGTH + self.payload.len();

        let mut eth = unsafe { Eth::new_unchecked(vec![0; len]) };

        eth.src_mut().set(self.src.unwrap_or_default());
        eth.dst_mut().set(self.dst.unwrap_or_default());
        eth.eth_type_mut().set(self.eth_type.unwrap_or_default());
        eth.payload_mut().copy_from_slice(self.payload.as_ref());

        eth
    }
}

/// Create an Eth layer with the given fields.
///
/// # Example
///
/// ```
/// # use netkit_packet::prelude::*;
/// let eth = eth!(
///     dst: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB],
///     src: [0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67],
///     eth_type: EthType::Ipv4,
///     payload: [0x01, 0x02, 0x03, 0x04]
/// );
///
/// assert_eq!(eth.dst().get(), eth_addr!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
/// assert_eq!(eth.src().get(), [0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67].into());
/// assert_eq!(eth.eth_type().get(), EthType::Ipv4);
/// assert_eq!(eth.payload(), [0x01, 0x02, 0x03, 0x04]);
/// ```
#[macro_export]
macro_rules! eth {
    ($($field : ident : $value : expr),* $(,)? ) => {
        $crate::layer::eth::EthBuilder::new()
            $(.$field($value))*
            .build()
    };
}

#[cfg(test)]
mod tests {

    use crate::eth_addr;
    use crate::prelude::*;

    #[test]
    fn eth_new_unchecked() {
        let data: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // dst mac
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, // src mac
            0x08, 0x00, // eth type ipv4
        ];

        let eth = unsafe { Eth::new_unchecked(data) };

        assert_eq!(
            eth.dst().get(),
            eth_addr!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB)
        );
        assert_eq!(eth.src().get(), eth_addr!("CD:EF:01:23:45:67"));
        assert_eq!(eth.eth_type().get(), EthType::Ipv4);
        assert_eq!(eth.payload().len(), 0);
    }

    #[test]
    fn eth_macro() {
        let eth = eth!(
            dst: eth_addr!([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]),
            src: [0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67],
            eth_type: EthType::Ipv4,
            payload: [0x01, 0x02, 0x03, 0x04]
        );

        assert_eq!(
            eth.dst().get(),
            EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB)
        );
        assert_eq!(eth.src().get(), [0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67].into());
        assert_eq!(eth.eth_type().get(), EthType::Ipv4);
        assert_eq!(eth.payload(), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn eth_set_fields() {
        let data: Vec<u8> = vec![0; 14];

        let mut eth = unsafe { Eth::new_unchecked(data) };

        eth.dst_mut()
            .set(eth_addr!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
        eth.src_mut()
            .set(eth_addr!(0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67));
        eth.eth_type_mut().set(EthType::Ipv4);

        assert_eq!(eth.dst().get(), eth_addr!("01:23:45:67:89:AB"));
        assert_eq!(eth.src().get(), eth_addr!("CD:EF:01:23:45:67"));
        assert_eq!(eth.eth_type().get(), EthType::Ipv4);
    }

    #[test]
    fn eth_new() {
        let data: [u8; 46] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst mac
            0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // src mac
            0x08, 0x00, // eth type ipv4
            0x45, // version 4, ihl 5
            0x00, // dscp 0, ecn 0
            0x00, 0x20, // total length 20 + 8 + 4 = 32
            0x00, 0x00, // identification 0
            0x00, 0x00, // flags 0, fragment offset 0
            0x40, // ttl 64
            0x11, // protocol udp
            0x00, 0x00, // checksum 0 (TODO: check this)
            0x7f, 0x00, 0x00, 0x01, // src ip
            0x7f, 0x00, 0x00, 0x02, // dst ip
            0x04, 0xd2, 0x04, 0xd3, // src port 1234, dst port 1235
            0x00, 0x0c, // length 12
            0x00, 0x00, // checksum 0 (TODO: check this)
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let eth = Eth::new(data).unwrap();

        assert_eq!(
            eth.dst().get(),
            eth_addr!(0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
        );
        assert_eq!(
            eth.src().get(),
            eth_addr!(0x06, 0x05, 0x04, 0x03, 0x02, 0x01)
        );
        assert_eq!(eth.eth_type().get(), EthType::Ipv4);

        let ipv4 = eth.ipv4().unwrap();

        assert_eq!(ipv4.ihl().get(), 5);
        assert_eq!(ipv4.protocol().get(), IpProtocol::Udp);
    }

    #[test]
    fn eth_debug() {
        let eth = eth!(
            dst: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB],
            src: [0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67],
            eth_type: EthType::Ipv4,
        );

        assert_eq!(
            format!("{:?}", eth),
            "Eth { dst: 01:23:45:67:89:AB, src: CD:EF:01:23:45:67, eth_type: Ipv4 }"
        );
    }
}
