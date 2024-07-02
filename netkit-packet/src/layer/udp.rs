use crate::{field_spec, prelude::*};

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum UdpError {
    #[error("Invalid Udp length: Length {0} is less than 8")]
    InvalidLength(usize),

    #[error("Invalid Udp checksum")]
    InvalidChecksum,
}

field_spec!(PortSpec, u16, u16);
field_spec!(LengthSpec, u16, u16);
field_spec!(ChecksumSpec, u16, u16);

pub const MIN_HEADER_LENGTH: usize = 8;

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
    pub const FIELD_SRC_PORT: core::ops::Range<usize> = 0..2;
    pub const FIELD_DST_PORT: core::ops::Range<usize> = 2..4;
    pub const FIELD_LENGTH: core::ops::Range<usize> = 4..6;
    pub const FIELD_CHECKSUM: core::ops::Range<usize> = 6..8;
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

    pub fn validate(&self) -> Result<(), UdpError> {
        if self.data.as_ref().len() < MIN_HEADER_LENGTH {
            return Err(UdpError::InvalidLength(self.data.as_ref().len()));
        }

        Ok(())
    }

    #[inline]
    pub fn new(data: T) -> Result<Self, UdpError> {
        let res = unsafe { Self::new_unchecked(data) };
        res.validate()?;
        Ok(res)
    }

    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    #[inline]
    pub fn src_port(&self) -> &Field<PortSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_SRC_PORT].as_ptr() as *const Field<PortSpec>) }
    }

    #[inline]
    pub fn dst_port(&self) -> &Field<PortSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DST_PORT].as_ptr() as *const Field<PortSpec>) }
    }

    #[inline]
    pub fn length(&self) -> &Field<LengthSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_LENGTH].as_ptr() as *const Field<LengthSpec>) }
    }

    #[inline]
    pub fn checksum(&self) -> &Field<ChecksumSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_CHECKSUM].as_ptr() as *const Field<ChecksumSpec>)
        }
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_PAYLOAD]
    }
}

impl<T> Udp<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    #[inline]
    pub fn src_port_mut(&mut self) -> &mut Field<PortSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_SRC_PORT].as_mut_ptr() as *mut Field<PortSpec>)
        }
    }

    #[inline]
    pub fn dst_port_mut(&mut self) -> &mut Field<PortSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_DST_PORT].as_mut_ptr() as *mut Field<PortSpec>)
        }
    }

    #[inline]
    pub fn length_mut(&mut self) -> &mut Field<LengthSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_LENGTH].as_mut_ptr() as *mut Field<LengthSpec>)
        }
    }

    #[inline]
    pub fn checksum_mut(&mut self) -> &mut Field<ChecksumSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_CHECKSUM].as_mut_ptr()
                as *mut Field<ChecksumSpec>)
        }
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_PAYLOAD]
    }
}

layer_impl!(Udp);

#[derive(Clone, Debug)]
pub struct UdpBuilder<T>
where
    T: AsRef<[u8]>,
{
    src_port: Option<u16>,
    dst_port: Option<u16>,
    length: Option<u16>,
    checksum: Option<u16>,
    payload: Option<T>,
}

impl<T> Default for UdpBuilder<T>
where
    T: AsRef<[u8]>,
{
    fn default() -> Self {
        Self {
            src_port: None,
            dst_port: None,
            length: None,
            checksum: None,
            payload: None,
        }
    }
}

impl<T> UdpBuilder<T>
where
    T: AsRef<[u8]>,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn src_port(&mut self, src_port: impl Into<u16>) -> &mut Self {
        self.src_port = Some(src_port.into());
        self
    }

    pub fn dst_port(&mut self, dst_port: impl Into<u16>) -> &mut Self {
        self.dst_port = Some(dst_port.into());
        self
    }

    pub fn length(&mut self, length: impl Into<u16>) -> &mut Self {
        self.length = Some(length.into());
        self
    }

    pub fn checksum(&mut self, checksum: impl Into<u16>) -> &mut Self {
        self.checksum = Some(checksum.into());
        self
    }

    pub fn payload(&mut self, payload: T) -> &mut Self {
        self.payload = Some(payload);
        self
    }

    pub fn build(&self) -> Udp<Vec<u8>> {
        // Calculate the length if not provided
        let len = self.length.unwrap_or(
            MIN_HEADER_LENGTH as u16
                + self
                    .payload
                    .as_ref()
                    .map(|p| p.as_ref().len() as u16)
                    .unwrap_or_default(),
        );

        let mut udp = unsafe { Udp::new_unchecked(vec![0; len as usize]) };

        udp.src_port_mut().set(self.src_port.unwrap_or_default());
        udp.dst_port_mut().set(self.dst_port.unwrap_or_default());
        udp.length_mut().set(len);
        // TODO: Calculate checksum
        udp.checksum_mut().set(self.checksum.unwrap_or_default());

        udp.payload_mut().copy_from_slice(
            self.payload
                .as_ref()
                .map(|p| p.as_ref())
                .unwrap_or_default(),
        );

        udp
    }
}

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
