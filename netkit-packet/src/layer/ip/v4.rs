use core::net::Ipv4Addr;

use super::IpProtocol;
use crate::{field_spec, impl_target, prelude::*};

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum Ipv4Error {
    #[error("Invalid Ipv4 length: Length {0} is less than minimum 20")]
    InvalidLength(usize),
}

impl_target!(frominto, core::net::Ipv4Addr, u32);

field_spec!(VersionSpec, u8, u8, 0xF0, 4);
field_spec!(IhlSpec, u8, u8, 0x0F);
field_spec!(DscpSpec, u8, u8, 0xFC, 2);
field_spec!(EcnSpec, u8, u8, 0x03);
field_spec!(TotalLengthSpec, u16, u16);
field_spec!(IdentificationSpec, u16, u16);
field_spec!(FlagsSpec, u8, u8, 0xE0, 5);
field_spec!(FragmentOffsetSpec, u16, u16, 0x1FFF);
field_spec!(TtlSpec, u8, u8);
field_spec!(ProtocolSpec, IpProtocol, u8, 0xFF);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(Ipv4AddrSpec, core::net::Ipv4Addr, u32);

pub struct Ipv4<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Ipv4<T>
where
    T: AsRef<[u8]>,
{
    pub const FIELD_VERSION: core::ops::Range<usize> = 0..1;
    pub const FIELD_IHL: core::ops::Range<usize> = 0..1;
    pub const FIELD_DSCP: core::ops::Range<usize> = 1..2;
    pub const FIELD_ECN: core::ops::Range<usize> = 1..2;
    pub const FIELD_TOTAL_LENGTH: core::ops::Range<usize> = 2..4;
    pub const FIELD_IDENTIFICATION: core::ops::Range<usize> = 4..6;
    pub const FIELD_FLAGS: core::ops::Range<usize> = 6..7;
    pub const FIELD_FRAGMENT_OFFSET: core::ops::Range<usize> = 6..8;
    pub const FIELD_TTL: core::ops::Range<usize> = 8..9;
    pub const FIELD_PROTOCOL: core::ops::Range<usize> = 9..10;
    pub const FIELD_CHECKSUM: core::ops::Range<usize> = 10..12;
    pub const FIELD_SRC: core::ops::Range<usize> = 12..16;
    pub const FIELD_DST: core::ops::Range<usize> = 16..20;

    pub const MIN_HEADER_LENGTH: usize = 20;

    /// Create a new Ipv4 layer without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid Ipv4 packet.
    ///
    /// The data must be at least 20 bytes long and the IHL field must be set
    /// correctly. Otherwise, the following methods may panic when accessing the
    /// fields.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    pub fn validate(&self) -> Result<(), Ipv4Error> {
        let data = self.data.as_ref();
        if data.len() < Self::MIN_HEADER_LENGTH {
            return Err(Ipv4Error::InvalidLength(data.len()));
        }

        // TODO: validate ihl, checksum, etc.

        Ok(())
    }

    #[inline]
    pub fn new(data: T) -> Result<Self, Ipv4Error> {
        let res = unsafe { Self::new_unchecked(data) };
        res.validate()?;
        Ok(res)
    }

    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    #[inline]
    pub fn version(&self) -> &Field<VersionSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_VERSION].as_ptr() as *const Field<VersionSpec>) }
    }

    #[inline]
    pub fn ihl(&self) -> &Field<IhlSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_IHL].as_ptr() as *const Field<IhlSpec>) }
    }

    #[inline]
    pub fn dscp(&self) -> &Field<DscpSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DSCP].as_ptr() as *const Field<DscpSpec>) }
    }

    #[inline]
    pub fn ecn(&self) -> &Field<EcnSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_ECN].as_ptr() as *const Field<EcnSpec>) }
    }

    #[inline]
    pub fn total_length(&self) -> &Field<TotalLengthSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_TOTAL_LENGTH].as_ptr()
                as *const Field<TotalLengthSpec>)
        }
    }

    #[inline]
    pub fn identification(&self) -> &Field<IdentificationSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_IDENTIFICATION].as_ptr()
                as *const Field<IdentificationSpec>)
        }
    }

    #[inline]
    pub fn flags(&self) -> &Field<FlagsSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const Field<FlagsSpec>) }
    }

    #[inline]
    pub fn fragment_offset(&self) -> &Field<FragmentOffsetSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_FRAGMENT_OFFSET].as_ptr()
                as *const Field<FragmentOffsetSpec>)
        }
    }

    #[inline]
    pub fn ttl(&self) -> &Field<TtlSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_TTL].as_ptr() as *const Field<TtlSpec>) }
    }

    #[inline]
    pub fn protocol(&self) -> &Field<ProtocolSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_PROTOCOL].as_ptr() as *const Field<ProtocolSpec>)
        }
    }

    #[inline]
    pub fn checksum(&self) -> &Field<ChecksumSpec> {
        unsafe {
            &*(self.data.as_ref()[Self::FIELD_CHECKSUM].as_ptr() as *const Field<ChecksumSpec>)
        }
    }

    #[inline]
    pub fn src(&self) -> &Field<Ipv4AddrSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_SRC].as_ptr() as *const Field<Ipv4AddrSpec>) }
    }

    #[inline]
    pub fn dst(&self) -> &Field<Ipv4AddrSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DST].as_ptr() as *const Field<Ipv4AddrSpec>) }
    }

    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.data.as_ref()[Self::MIN_HEADER_LENGTH..(self.ihl().get() - 5) as usize * 4]
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[self.ihl().get() as usize * 4..]
    }

    pub fn tcp(&self) -> Option<Tcp<&[u8]>> {
        if self.protocol().get() == IpProtocol::Tcp {
            Tcp::new(self.payload()).ok()
        } else {
            None
        }
    }

    pub fn udp(&self) -> Option<Udp<&[u8]>> {
        if self.protocol().get() == IpProtocol::Udp {
            Udp::new(self.payload()).ok()
        } else {
            None
        }
    }
}

impl<T> Ipv4<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    #[inline]
    pub fn version_mut(&mut self) -> &mut Field<VersionSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_VERSION].as_mut_ptr() as *mut Field<VersionSpec>)
        }
    }

    #[inline]
    pub fn ihl_mut(&mut self) -> &mut Field<IhlSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_IHL].as_mut_ptr() as *mut Field<IhlSpec>) }
    }

    #[inline]
    pub fn dscp_mut(&mut self) -> &mut Field<DscpSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_DSCP].as_mut_ptr() as *mut Field<DscpSpec>) }
    }

    #[inline]
    pub fn ecn_mut(&mut self) -> &mut Field<EcnSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_ECN].as_mut_ptr() as *mut Field<EcnSpec>) }
    }

    #[inline]
    pub fn total_length_mut(&mut self) -> &mut Field<TotalLengthSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_TOTAL_LENGTH].as_mut_ptr()
                as *mut Field<TotalLengthSpec>)
        }
    }

    #[inline]
    pub fn identification_mut(&mut self) -> &mut Field<IdentificationSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_IDENTIFICATION].as_mut_ptr()
                as *mut Field<IdentificationSpec>)
        }
    }

    #[inline]
    pub fn flags_mut(&mut self) -> &mut Field<FlagsSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut Field<FlagsSpec>)
        }
    }

    #[inline]
    pub fn fragment_offset_mut(&mut self) -> &mut Field<FragmentOffsetSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_FRAGMENT_OFFSET].as_mut_ptr()
                as *mut Field<FragmentOffsetSpec>)
        }
    }

    #[inline]
    pub fn ttl_mut(&mut self) -> &mut Field<TtlSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_TTL].as_mut_ptr() as *mut Field<TtlSpec>) }
    }

    #[inline]
    pub fn protocol_mut(&mut self) -> &mut Field<ProtocolSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_PROTOCOL].as_mut_ptr()
                as *mut Field<ProtocolSpec>)
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
    pub fn src_mut(&mut self) -> &mut Field<Ipv4AddrSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_SRC].as_mut_ptr() as *mut Field<Ipv4AddrSpec>)
        }
    }

    #[inline]
    pub fn dst_mut(&mut self) -> &mut Field<Ipv4AddrSpec> {
        unsafe {
            &mut *(self.data.as_mut()[Self::FIELD_DST].as_mut_ptr() as *mut Field<Ipv4AddrSpec>)
        }
    }

    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let range = Self::MIN_HEADER_LENGTH..self.ihl().get() as usize * 4;
        &mut self.data.as_mut()[range]
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.ihl().get() as usize * 4..;
        &mut self.data.as_mut()[range]
    }
}

layer_impl!(Ipv4);

#[derive(Clone, Debug)]
pub struct Ipv4Builder<T = Vec<u8>>
where
    T: AsRef<[u8]>,
{
    ihl: Option<u8>,
    dscp: Option<u8>,
    ecn: Option<u8>,
    total_length: Option<u16>,
    identification: Option<u16>,
    flags: Option<u8>,
    fragment_offset: Option<u16>,
    ttl: Option<u8>,
    protocol: Option<IpProtocol>,
    checksum: Option<u16>,
    src: Option<Ipv4Addr>,
    dst: Option<Ipv4Addr>,
    options: Option<T>,
    payload: Option<T>,
}

impl<T> Default for Ipv4Builder<T>
where
    T: AsRef<[u8]>,
{
    fn default() -> Self {
        Self {
            ihl: None,
            dscp: None,
            ecn: None,
            total_length: None,
            identification: None,
            flags: None,
            fragment_offset: None,
            ttl: None,
            protocol: None,
            checksum: None,
            src: None,
            dst: None,
            options: None,
            payload: None,
        }
    }
}

impl<T> Ipv4Builder<T>
where
    T: AsRef<[u8]>,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ihl(&mut self, ihl: impl Into<u8>) -> &mut Self {
        self.ihl = Some(ihl.into());
        self
    }

    pub fn dscp(&mut self, dscp: impl Into<u8>) -> &mut Self {
        self.dscp = Some(dscp.into());
        self
    }

    pub fn ecn(&mut self, ecn: impl Into<u8>) -> &mut Self {
        self.ecn = Some(ecn.into());
        self
    }

    pub fn total_length(&mut self, total_length: impl Into<u16>) -> &mut Self {
        self.total_length = Some(total_length.into());
        self
    }

    pub fn identification(&mut self, identification: impl Into<u16>) -> &mut Self {
        self.identification = Some(identification.into());
        self
    }

    pub fn flags(&mut self, flags: impl Into<u8>) -> &mut Self {
        self.flags = Some(flags.into());
        self
    }

    pub fn fragment_offset(&mut self, fragment_offset: impl Into<u16>) -> &mut Self {
        self.fragment_offset = Some(fragment_offset.into());
        self
    }

    pub fn ttl(&mut self, ttl: impl Into<u8>) -> &mut Self {
        self.ttl = Some(ttl.into());
        self
    }

    pub fn protocol(&mut self, protocol: IpProtocol) -> &mut Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn checksum(&mut self, checksum: impl Into<u16>) -> &mut Self {
        self.checksum = Some(checksum.into());
        self
    }

    pub fn src(&mut self, src: Ipv4Addr) -> &mut Self {
        self.src = Some(src);
        self
    }

    pub fn dst(&mut self, dst: Ipv4Addr) -> &mut Self {
        self.dst = Some(dst);
        self
    }

    pub fn options(&mut self, options: T) -> &mut Self {
        self.options = Some(options);
        self
    }

    pub fn payload(&mut self, payload: T) -> &mut Self {
        self.payload = Some(payload);
        self
    }

    pub fn build(&self) -> Ipv4<Vec<u8>> {
        // Calculate the ihl
        // 1. if ihl is set, use it
        // 2. if ihl is not set, calculate it from the options
        // 3. if options is not set, use the minimum header length
        let ihl = self.ihl.unwrap_or(
            self.options
                .as_ref()
                .map_or(5, |p| p.as_ref().len() as u8 / 4 + 5),
        );

        // Calculate the total length
        let length = self.total_length.unwrap_or(
            ihl as u16 * 4
                + self
                    .payload
                    .as_ref()
                    .map(|p| p.as_ref().len() as u16)
                    .unwrap_or(0),
        );

        let mut ipv4 = unsafe { Ipv4::new_unchecked(vec![0; length as usize]) };

        ipv4.version_mut().set(4);
        ipv4.ihl_mut().set(ihl);
        ipv4.dscp_mut().set(self.dscp.unwrap_or(0));
        ipv4.ecn_mut().set(self.ecn.unwrap_or(0));
        ipv4.total_length_mut().set(length);
        ipv4.identification_mut()
            .set(self.identification.unwrap_or(0));
        ipv4.flags_mut().set(self.flags.unwrap_or(0));
        ipv4.fragment_offset_mut()
            .set(self.fragment_offset.unwrap_or(0));
        ipv4.ttl_mut().set(self.ttl.unwrap_or(64));
        ipv4.protocol_mut()
            .set(self.protocol.unwrap_or(IpProtocol::Reserved(255)));
        ipv4.checksum_mut().set(self.checksum.unwrap_or(0));
        ipv4.src_mut()
            .set(self.src.unwrap_or(Ipv4Addr::UNSPECIFIED));
        ipv4.dst_mut()
            .set(self.dst.unwrap_or(Ipv4Addr::UNSPECIFIED));
        ipv4.options_mut()
            .copy_from_slice(self.options.as_ref().map_or(&[], |p| p.as_ref()));
        ipv4.payload_mut()
            .copy_from_slice(self.payload.as_ref().map_or(&[], |p| p.as_ref()));

        ipv4
    }
}

#[macro_export]
macro_rules! ipv4 {
    ($($field : ident : $value : expr),* $(,)?) => {
        $crate::layer::ip::v4::Ipv4Builder::new()
            $(.$field($value))*
            .build()
    };
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use core::net::Ipv4Addr;

    #[test]
    fn ipv4_new_unchecked() {
        let data: [u8; 32] = [
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

        let ipv4 = unsafe { Ipv4::new_unchecked(data) };

        assert_eq!(ipv4.version().get(), 4);
        assert_eq!(ipv4.ihl().get(), 5);
        assert_eq!(ipv4.dscp().get(), 0);
        assert_eq!(ipv4.ecn().get(), 0);
        assert_eq!(ipv4.total_length().get(), 32);
        assert_eq!(ipv4.identification().get(), 0);
        assert_eq!(ipv4.flags().get(), 0);
        assert_eq!(ipv4.fragment_offset().get(), 0);
        assert_eq!(ipv4.ttl().get(), 64);
        assert_eq!(ipv4.protocol().get(), IpProtocol::Udp);
        assert_eq!(ipv4.checksum().get(), 0);
        assert_eq!(ipv4.src().get(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4.dst().get(), Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(
            ipv4.payload(),
            &[0x04, 0xd2, 0x04, 0xd3, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn ipv4_macro() {
        let ipv4 = ipv4!(
            src: Ipv4Addr::new(10, 0, 1, 2),
            dst: Ipv4Addr::new(10, 0, 1, 3),
            protocol: IpProtocol::Udp,
            payload: vec![1, 2, 3, 4],
        );

        assert_eq!(ipv4.ihl().get(), 5);
        assert_eq!(ipv4.total_length().get(), 20 + 4);

        assert_eq!(ipv4.src().get(), Ipv4Addr::new(10, 0, 1, 2));
        assert_eq!(ipv4.dst().get(), Ipv4Addr::new(10, 0, 1, 3));
        assert_eq!(ipv4.protocol().get(), IpProtocol::Udp);
        assert_eq!(ipv4.payload(), &[1, 2, 3, 4]);
    }
}
