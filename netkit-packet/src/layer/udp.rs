//! User Datagram Protocol (UDP) layer.

use crate::{field_spec, prelude::*};

/// Error type for Udp layer.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum UdpError {
    /// Invalid Udp length.
    #[error("Invalid Udp length: Length {0} is less than 8")]
    InvalidLength(usize),

    /// Invalid Udp checksum.
    #[error("Invalid Udp checksum")]
    InvalidChecksum,
}

field_spec!(PortSpec, u16, u16);
field_spec!(LengthSpec, u16, u16);
field_spec!(ChecksumSpec, u16, u16);

/// Minimum length of a Udp packet.
pub const MIN_HEADER_LENGTH: usize = 8;

/// User Datagram Protocol (UDP) layer.
pub struct Udp<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Udp<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the source port: 0..2
    pub const FIELD_SRC_PORT: core::ops::Range<usize> = 0..2;
    /// Field range of the destination port: 2..4
    pub const FIELD_DST_PORT: core::ops::Range<usize> = 2..4;
    /// Field range of the length: 4..6
    pub const FIELD_LENGTH: core::ops::Range<usize> = 4..6;
    /// Field range of the checksum: 6..8
    pub const FIELD_CHECKSUM: core::ops::Range<usize> = 6..8;
    /// Field range of the payload: 8..
    pub const FIELD_PAYLOAD: core::ops::RangeFrom<usize> = 8..;

    /// Create a new Udp layer without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid Udp packet.
    ///
    /// The length of the data must be at least 8 bytes. Otherwise, the
    /// following methods may panic when accessing the fields.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the Udp layer.
    pub fn validate(&self) -> Result<(), UdpError> {
        if self.data.as_ref().len() < MIN_HEADER_LENGTH {
            return Err(UdpError::InvalidLength(self.data.as_ref().len()));
        }

        Ok(())
    }

    /// Create a new Udp layer.
    #[inline]
    pub fn new(data: T) -> Result<Self, UdpError> {
        let res = unsafe { Self::new_unchecked(data) };
        res.validate()?;
        Ok(res)
    }

    /// Get the inner raw data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the source port.
    #[inline]
    pub fn src_port(&self) -> &Field<PortSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_SRC_PORT].as_ptr() as *const Field<PortSpec>) }
    }

    /// Get the accessor of the destination port.
    #[inline]
    pub fn dst_port(&self) -> &Field<PortSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DST_PORT].as_ptr() as *const Field<PortSpec>) }
    }

    /// Get the accessor of the length.
    #[inline]
    pub fn length(&self) -> &Field<LengthSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_LENGTH].as_ptr() as *const Field<LengthSpec>) }
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> &Field<ChecksumSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_CHECKSUM].as_ptr() as *const Field<ChecksumSpec>)
        }
    }

    /// Get the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_PAYLOAD]
    }
}

impl<T> Udp<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the source port.
    #[inline]
    pub fn src_port_mut(&mut self) -> &mut Field<PortSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_SRC_PORT].as_mut_ptr() as *mut Field<PortSpec>)
        }
    }

    /// Get the mutable accessor of the destination port.
    #[inline]
    pub fn dst_port_mut(&mut self) -> &mut Field<PortSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_DST_PORT].as_mut_ptr() as *mut Field<PortSpec>)
        }
    }

    /// Get the mutable accessor of the length.
    #[inline]
    pub fn length_mut(&mut self) -> &mut Field<LengthSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_LENGTH].as_mut_ptr() as *mut Field<LengthSpec>)
        }
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> &mut Field<ChecksumSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_CHECKSUM].as_mut_ptr()
                as *mut Field<ChecksumSpec>)
        }
    }

    /// Get the mutable payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_PAYLOAD]
    }
}

layer_impl!(Udp);

/// Builder for [`Udp`].
#[derive(Clone, Debug, Default)]
pub struct UdpBuilder {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    length: Option<u16>,
    checksum: Option<u16>,
    payload: Vec<u8>,
}

impl UdpBuilder {
    /// Create a new Udp builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the source port.
    pub fn src_port(&mut self, src_port: impl Into<u16>) -> &mut Self {
        self.src_port = Some(src_port.into());
        self
    }

    /// Set the destination port.
    pub fn dst_port(&mut self, dst_port: impl Into<u16>) -> &mut Self {
        self.dst_port = Some(dst_port.into());
        self
    }

    /// Set the length.
    pub fn length(&mut self, length: impl Into<u16>) -> &mut Self {
        self.length = Some(length.into());
        self
    }

    /// Set the checksum.
    pub fn checksum(&mut self, checksum: impl Into<u16>) -> &mut Self {
        self.checksum = Some(checksum.into());
        self
    }

    /// Set the payload.
    pub fn payload<T: AsRef<[u8]>>(&mut self, payload: T) -> &mut Self {
        self.payload.extend_from_slice(payload.as_ref());
        self
    }

    /// Build a Udp layer.
    pub fn build(&self) -> Udp<Vec<u8>> {
        // Calculate the length if not provided
        let len = self
            .length
            .unwrap_or(MIN_HEADER_LENGTH as u16 + self.payload.len() as u16);

        let mut udp = unsafe { Udp::new_unchecked(vec![0; len as usize]) };

        udp.src_port_mut().set(self.src_port.unwrap_or_default());
        udp.dst_port_mut().set(self.dst_port.unwrap_or_default());
        udp.length_mut().set(len);
        // TODO: Calculate checksum
        udp.checksum_mut().set(self.checksum.unwrap_or_default());

        udp.payload_mut().copy_from_slice(self.payload.as_ref());

        udp
    }
}

/// Create a new Udp layer with the given fields.
#[macro_export]
macro_rules! udp {
    ($($field : ident : $value : expr),* $(,)? ) => {
        $crate::layer::udp::UdpBuilder::new()
            $(.$field($value))*
            .build()
    };
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn udp_new_unchecked() {
        let data: [u8; 10] = [
            0x00, 0x50, // src port
            0x00, 0x51, // dst port
            0x00, 0x0a, // length
            0x00, 0x00, // checksum
            0x01, 0x02, // payload
        ];

        let udp = unsafe { Udp::new_unchecked(data) };

        assert_eq!(udp.src_port().get(), 80);
        assert_eq!(udp.dst_port().get(), 81);
        assert_eq!(udp.length().get(), 10);
        assert_eq!(udp.checksum().get(), 0);
        assert_eq!(udp.payload(), &[0x01, 0x02]);
    }

    #[test]
    fn udp_macro() {
        let udp = udp!(
            src_port: 80u16,
            dst_port: 81u16,
            length: 10u16,
            checksum: 0u16,
            payload: [0x01, 0x02]
        );

        assert_eq!(udp.src_port().get(), 80);
        assert_eq!(udp.dst_port().get(), 81);
        assert_eq!(udp.length().get(), 10);
        assert_eq!(udp.checksum().get(), 0);
    }
}
