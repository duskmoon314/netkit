//! Transmission Control Protocol (TCP) layer.

use crate::{field_spec, prelude::*};

pub mod flags;
pub use flags::*;

/// Error type for Tcp layer.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum TcpError {
    /// Invalid Tcp length.
    #[error("Invalid Tcp length: Length {0} is less than 8")]
    InvalidLength(usize),
}

field_spec!(PortSpec, u16, u16);
field_spec!(SeqNumSpec, u32, u32);
field_spec!(AckNumSpec, u32, u32);
field_spec!(DataOffsetSpec, u8, u8, 0xF0, 4);
field_spec!(FlagsSpec, TcpFlags, u8);
field_spec!(WindowSizeSpec, u16, u16);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(UrgentPointerSpec, u16, u16);

/// Minimum length of a Tcp packet.
pub const MIN_HEADER_LENGTH: usize = 20;

/// Transmission Control Protocol (TCP) layer.
pub struct Tcp<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Tcp<T>
where
    T: AsRef<[u8]>,
{
    /// Field ranges of the source port: 0..2
    pub const FIELD_SRC_PORT: core::ops::Range<usize> = 0..2;
    /// Field ranges of the destination port: 2..4
    pub const FIELD_DST_PORT: core::ops::Range<usize> = 2..4;
    /// Field ranges of the sequence number: 4..8
    pub const FIELD_SEQ_NUM: core::ops::Range<usize> = 4..8;
    /// Field ranges of the acknowledgment number: 8..12
    pub const FIELD_ACK_NUM: core::ops::Range<usize> = 8..12;
    /// Field ranges of the data offset: 12..13
    pub const FIELD_DATA_OFFSET: core::ops::Range<usize> = 12..13;
    /// Field ranges of the flags: 13..14
    pub const FIELD_FLAGS: core::ops::Range<usize> = 13..14;
    /// Field ranges of the window size: 14..16
    pub const FIELD_WINDOW_SIZE: core::ops::Range<usize> = 14..16;
    /// Field ranges of the checksum: 16..18
    pub const FIELD_CHECKSUM: core::ops::Range<usize> = 16..18;
    /// Field ranges of the urgent pointer: 18..20
    pub const FIELD_URGENT_POINTER: core::ops::Range<usize> = 18..20;

    /// Create a new Tcp layer without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid Tcp packet.
    ///
    /// The length of the data must be at least 20 bytes and the data offset
    /// must be set correctly. Otherwise, the following methods may panic when
    /// accessing the fields.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the Tcp layer.
    pub fn validate(&self) -> Result<(), TcpError> {
        if self.data.as_ref().len() < MIN_HEADER_LENGTH {
            return Err(TcpError::InvalidLength(self.data.as_ref().len()));
        }

        // TODO: validate data offset, checksum, etc.

        Ok(())
    }

    /// Create a new Tcp layer from raw data.
    #[inline]
    pub fn new(data: T) -> Result<Self, TcpError> {
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

    /// Get the accessor of the sequence number.
    #[inline]
    pub fn seq_num(&self) -> &Field<SeqNumSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_SEQ_NUM].as_ptr() as *const Field<SeqNumSpec>) }
    }

    /// Get the accessor of the acknowledgment number.
    #[inline]
    pub fn ack_num(&self) -> &Field<AckNumSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_ACK_NUM].as_ptr() as *const Field<AckNumSpec>) }
    }

    /// Get the accessor of the data offset.
    #[inline]
    pub fn data_offset(&self) -> &Field<DataOffsetSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_DATA_OFFSET].as_ptr() as *const Field<DataOffsetSpec>)
        }
    }

    /// Get the accessor of the flags.
    #[inline]
    pub fn flags(&self) -> &Field<FlagsSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const Field<FlagsSpec>) }
    }

    /// Get the accessor of the window size.
    #[inline]
    pub fn window_size(&self) -> &Field<WindowSizeSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_WINDOW_SIZE].as_ptr() as *const Field<WindowSizeSpec>)
        }
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> &Field<ChecksumSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_CHECKSUM].as_ptr() as *const Field<ChecksumSpec>)
        }
    }

    /// Get the accessor of the urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> &Field<UrgentPointerSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_URGENT_POINTER].as_ptr()
                as *const Field<UrgentPointerSpec>)
        }
    }

    /// Get the options.
    #[inline]
    pub fn options(&self) -> &[u8] {
        let range = MIN_HEADER_LENGTH..self.data_offset().get() as usize * 4;
        &self.data.as_ref()[range]
    }

    /// Get the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let range = self.data_offset().get() as usize * 4..;
        &self.data.as_ref()[range]
    }
}

impl<T> Tcp<T>
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

    /// Get the mutable accessor of the sequence number.
    #[inline]
    pub fn seq_num_mut(&mut self) -> &mut Field<SeqNumSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_SEQ_NUM].as_mut_ptr() as *mut Field<SeqNumSpec>)
        }
    }

    /// Get the mutable accessor of the acknowledgment number.
    #[inline]
    pub fn ack_num_mut(&mut self) -> &mut Field<AckNumSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_ACK_NUM].as_mut_ptr() as *mut Field<AckNumSpec>)
        }
    }

    /// Get the mutable accessor of the data offset.
    #[inline]
    pub fn data_offset_mut(&mut self) -> &mut Field<DataOffsetSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_DATA_OFFSET].as_mut_ptr()
                as *mut Field<DataOffsetSpec>)
        }
    }

    /// Get the mutable accessor of the flags.
    #[inline]
    pub fn flags_mut(&mut self) -> &mut Field<FlagsSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut Field<FlagsSpec>)
        }
    }

    /// Get the mutable accessor of the window size.
    #[inline]
    pub fn window_size_mut(&mut self) -> &mut Field<WindowSizeSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_WINDOW_SIZE].as_mut_ptr()
                as *mut Field<WindowSizeSpec>)
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

    /// Get the mutable accessor of the urgent pointer.
    #[inline]
    pub fn urgent_pointer_mut(&mut self) -> &mut Field<UrgentPointerSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_URGENT_POINTER].as_mut_ptr()
                as *mut Field<UrgentPointerSpec>)
        }
    }

    /// Get the mutable options.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let range = MIN_HEADER_LENGTH..self.data_offset().get() as usize * 4;
        &mut self.data.as_mut()[range]
    }

    /// Get the mutable payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.data_offset().get() as usize * 4..;
        &mut self.data.as_mut()[range]
    }
}

layer_impl!(Tcp);

/// Builder for [`Tcp`].
#[derive(Clone, Debug, Default)]
pub struct TcpBuilder {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    seq_num: Option<u32>,
    ack_num: Option<u32>,
    data_offset: Option<u8>,
    flags: Option<TcpFlags>,
    window_size: Option<u16>,
    checksum: Option<u16>,
    urgent_pointer: Option<u16>,
    options: Vec<u8>,
    payload: Vec<u8>,
}

impl TcpBuilder {
    /// Create a new Tcp builder.
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

    /// Set the sequence number.
    pub fn seq_num(&mut self, seq_num: impl Into<u32>) -> &mut Self {
        self.seq_num = Some(seq_num.into());
        self
    }

    /// Set the acknowledgment number.
    pub fn ack_num(&mut self, ack_num: impl Into<u32>) -> &mut Self {
        self.ack_num = Some(ack_num.into());
        self
    }

    /// Set the data offset.
    pub fn data_offset(&mut self, data_offset: impl Into<u8>) -> &mut Self {
        self.data_offset = Some(data_offset.into());
        self
    }

    /// Set the flags.
    pub fn flags(&mut self, flags: impl Into<TcpFlags>) -> &mut Self {
        self.flags = Some(flags.into());
        self
    }

    /// Set the window size.
    pub fn window_size(&mut self, window_size: impl Into<u16>) -> &mut Self {
        self.window_size = Some(window_size.into());
        self
    }

    /// Set the checksum.
    pub fn checksum(&mut self, checksum: impl Into<u16>) -> &mut Self {
        self.checksum = Some(checksum.into());
        self
    }

    /// Set the urgent pointer.
    pub fn urgent_pointer(&mut self, urgent_pointer: impl Into<u16>) -> &mut Self {
        self.urgent_pointer = Some(urgent_pointer.into());
        self
    }

    /// Set the options.
    pub fn options<T: AsRef<[u8]>>(&mut self, options: T) -> &mut Self {
        self.options.extend_from_slice(options.as_ref());
        self
    }

    /// Set the payload.
    pub fn payload<T: AsRef<[u8]>>(&mut self, payload: T) -> &mut Self {
        self.payload.extend_from_slice(payload.as_ref());
        self
    }

    /// Build the Tcp layer.
    pub fn build(&self) -> Tcp<Vec<u8>> {
        // Calculate the data offset
        let data_offset = self.data_offset.unwrap_or(self.options.len() as u8 / 4 + 5);

        let mut tcp =
            unsafe { Tcp::new_unchecked(vec![0; data_offset as usize * 4 + self.payload.len()]) };

        tcp.src_port_mut().set(self.src_port.unwrap_or_default());
        tcp.dst_port_mut().set(self.dst_port.unwrap_or_default());
        tcp.seq_num_mut().set(self.seq_num.unwrap_or_default());
        tcp.ack_num_mut().set(self.ack_num.unwrap_or_default());
        tcp.data_offset_mut().set(data_offset);
        tcp.flags_mut().set(self.flags.unwrap_or_default());
        tcp.window_size_mut().set(self.window_size.unwrap_or(64));
        tcp.checksum_mut().set(self.checksum.unwrap_or_default());
        tcp.urgent_pointer_mut()
            .set(self.urgent_pointer.unwrap_or_default());

        tcp.options_mut().copy_from_slice(self.options.as_ref());
        tcp.payload_mut().copy_from_slice(self.payload.as_ref());

        tcp
    }
}

/// Create a new Tcp layer with the given fields.
#[macro_export]
macro_rules! tcp {
    ($($field : ident : $value : expr),* $(,)?) => {
        $crate::layer::tcp::TcpBuilder::new()
            $(.$field($value))*
            .build()
    };
}

#[cfg(test)]
mod tests {
    use crate::{layer::tcp::TcpFlags, prelude::*};

    #[test]
    fn tcp_new_unchecked() {
        let data: [u8; 24] = [
            0x00, 0x50, // src_port = 80
            0x00, 0x60, // dst_port = 96
            0x00, 0x00, 0x00, 0x00, // seq_num = 0
            0x00, 0x00, 0x00, 0x00, // ack_num = 0
            0x50, // data_offset = 5, reserved = 0
            0x02, // flags = 2, SYN
            0x20, 0x00, // window_size = 8192
            0x00, 0x00, // checksum = 0
            0x00, 0x00, // urgent_pointer = 0
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let tcp = unsafe { Tcp::new_unchecked(data) };

        assert_eq!(tcp.src_port().get(), 80);
        assert_eq!(tcp.dst_port().get(), 96);
        assert_eq!(tcp.seq_num().get(), 0);
        assert_eq!(tcp.ack_num().get(), 0);
        assert_eq!(tcp.data_offset().get(), 5);
        assert_eq!(tcp.flags().get(), TcpFlags::SYN);
        assert_eq!(tcp.window_size().get(), 8192);
        assert_eq!(tcp.checksum().get(), 0);
        assert_eq!(tcp.urgent_pointer().get(), 0);
        assert_eq!(tcp.payload(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn tcp_macro() {
        let tcp = tcp! {
            src_port: 80u16,
            dst_port: 96u16,
            payload: [0x01, 0x02, 0x03, 0x04],
        };

        assert_eq!(tcp.src_port().get(), 80);
        assert_eq!(tcp.dst_port().get(), 96);
        assert_eq!(tcp.data_offset().get(), 5);
        assert_eq!(tcp.flags().get(), TcpFlags::empty());
        assert_eq!(tcp.window_size().get(), 64);
        assert_eq!(tcp.checksum().get(), 0);
        assert_eq!(tcp.urgent_pointer().get(), 0);
        assert_eq!(tcp.payload(), &[0x01, 0x02, 0x03, 0x04]);
    }
}
