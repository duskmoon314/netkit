//! VLAN (IEEE 802.1Q) Layer

use crate::{field_spec, prelude::*};

/// Error type for Vlan layer.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum VlanError {
    /// Invalid Vlan length.
    #[error("Invalid Vlan length: Length {0} is not equal to 4")]
    InvalidLength(usize),
}

field_spec!(TciSpec, u16, u16);
field_spec!(PcpSpec, u8, u8, 0xC0, 5);
field_spec!(DeiSpec, bool, u8, 0x20, 4);
field_spec!(VidSpec, u16, u16, 0x0FFF, 0);
field_spec!(EthTypeSpec, EthType, u16);

/// Length of the Vlan 802.1Q header
pub const HEADER_LENGTH: usize = 4;

/// VLAN (IEEE 802.1Q) Layer
///
/// In the standard, the VLAN header is inserted between the MAC address and the
/// EthType field. That is:
///
/// ```text
/// +----------+---------+-------------+---------+
/// | MAC Dest | MAC Src | VLAN Header | EthType |
/// +----------+---------+-------------+---------+
/// ```
///
/// This is a bit complicated, so we view the VLAN header as another format:
///
/// ```text
/// +----------+---------+------------------+-----------------------------+
/// | MAC Dest | MAC Src | EthType (0x8100) | VLAN Header (TCI + EthType) |
/// +----------+---------+------------------+-----------------------------+
/// ```
pub struct Vlan<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Vlan<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the TCI: 0..2
    pub const FIELD_TCI: core::ops::Range<usize> = 0..2;
    /// Field range of the PCP: 0..1
    pub const FIELD_PCP: core::ops::Range<usize> = 0..1;
    /// Field range of the DEI: 0..1
    pub const FIELD_DEI: core::ops::Range<usize> = 0..1;
    /// Field range of the VID: 0..2
    pub const FIELD_VID: core::ops::Range<usize> = 0..2;
    /// Field range of the Ethertype: 2..4
    pub const FIELD_ETH_TYPE: core::ops::Range<usize> = 2..4;
    /// Field range of the payload: 4..
    pub const FIELD_PAYLOAD: core::ops::RangeFrom<usize> = 4..;

    /// Create a new VLAN layer without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid VLAN header.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the VLAN header.
    pub fn validate(&self) -> Result<(), VlanError> {
        if self.data.as_ref().len() < HEADER_LENGTH {
            return Err(VlanError::InvalidLength(self.data.as_ref().len()));
        }
        Ok(())
    }

    /// Create a new VLAN layer from raw data.
    #[inline]
    pub fn new(data: T) -> Result<Self, VlanError> {
        let vlan = unsafe { Self::new_unchecked(data) };
        vlan.validate()?;
        Ok(vlan)
    }

    /// Get the inner raw data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the TCI field.
    #[inline]
    pub fn tci(&self) -> &Field<TciSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_TCI])
    }

    /// Get the accessor of the PCP field.
    #[inline]
    pub fn pcp(&self) -> &Field<PcpSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_PCP])
    }

    /// Get the accessor of the DEI field.
    #[inline]
    pub fn dei(&self) -> &Field<DeiSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_DEI])
    }

    /// Get the accessor of the VID field.
    #[inline]
    pub fn vid(&self) -> &Field<VidSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_VID])
    }

    /// Get the accessor of the EthType field.
    #[inline]
    pub fn eth_type(&self) -> &Field<EthTypeSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_ETH_TYPE])
    }

    /// Get the payload
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

    /// Get the IPv4 layer from the given bytes if the Eth type is IPv4.
    pub fn ipv4_from_bytes(bytes: &[u8]) -> Option<Ipv4<&[u8]>> {
        let vlan = Vlan::new(bytes).ok()?;
        if vlan.eth_type().get() == EthType::Ipv4 {
            Ipv4::new(&bytes[Vlan::<&[u8]>::FIELD_PAYLOAD]).ok()
        } else {
            None
        }
    }
}

impl<T> Vlan<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the TCI field.
    #[inline]
    pub fn tci_mut(&mut self) -> &mut Field<TciSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_TCI])
    }

    /// Get the mutable accessor of the PCP field.
    #[inline]
    pub fn pcp_mut(&mut self) -> &mut Field<PcpSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_PCP])
    }

    /// Get the mutable accessor of the DEI field.
    #[inline]
    pub fn dei_mut(&mut self) -> &mut Field<DeiSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_DEI])
    }

    /// Get the mutable accessor of the VID field.
    #[inline]
    pub fn vid_mut(&mut self) -> &mut Field<VidSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_VID])
    }

    /// Get the mutable accessor of the EthType field.
    #[inline]
    pub fn eth_type_mut(&mut self) -> &mut Field<EthTypeSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_ETH_TYPE])
    }

    /// Get the mutable payload
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

    /// Get the mutable IPv4 layer from the given bytes if the Eth type is IPv4.
    pub fn ipv4_mut_from_bytes(bytes: &mut [u8]) -> Option<Ipv4<&mut [u8]>> {
        let vlan = Vlan::new(&mut *bytes).ok()?;
        if vlan.eth_type().get() == EthType::Ipv4 {
            Ipv4::new(&mut bytes[Vlan::<&mut [u8]>::FIELD_PAYLOAD]).ok()
        } else {
            None
        }
    }
}

layer_impl!(Vlan);

impl<T> core::fmt::Debug for Vlan<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Vlan");

        f.field("pcp", &self.pcp().get())
            .field("dei", &self.dei().get())
            .field("vid", &self.vid().get())
            .field("eth_type", &self.eth_type().get());

        // TODO: Print payload

        f.finish()
    }
}

/// Builder for [`Vlan`]
#[derive(Clone, Debug, Default)]
pub struct VlanBuilder {
    pcp: Option<u8>,
    dei: Option<bool>,
    vid: Option<u16>,
    eth_type: Option<EthType>,
    payload: Vec<u8>,
}

impl VlanBuilder {
    /// Create a new Vlan builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the PCP field.
    pub fn pcp(&mut self, pcp: impl Into<u8>) -> &mut Self {
        self.pcp = Some(pcp.into());
        self
    }

    /// Set the DEI field.
    pub fn dei(&mut self, dei: impl Into<bool>) -> &mut Self {
        self.dei = Some(dei.into());
        self
    }

    /// Set the VID field.
    pub fn vid(&mut self, vid: impl Into<u16>) -> &mut Self {
        self.vid = Some(vid.into());
        self
    }

    /// Set the TCI as a whole.
    pub fn tci(&mut self, tci: impl Into<u16>) -> &mut Self {
        let tci = tci.into();
        self.pcp = Some((tci >> 13) as u8);
        self.dei = Some(((tci >> 12) & 0x1) != 0);
        self.vid = Some(tci & 0xFFF);
        self
    }

    /// Set the EthType field.
    pub fn eth_type(&mut self, eth_type: impl Into<EthType>) -> &mut Self {
        self.eth_type = Some(eth_type.into());
        self
    }

    /// Set the payload.
    pub fn payload<T: AsRef<[u8]>>(&mut self, payload: T) -> &mut Self {
        self.payload.extend_from_slice(payload.as_ref());
        self
    }

    /// Build the Vlan layer.
    pub fn build(&self) -> Vlan<Vec<u8>> {
        let len = HEADER_LENGTH + self.payload.len();

        let mut vlan = unsafe { Vlan::new_unchecked(vec![0; len]) };

        vlan.pcp_mut().set(self.pcp.unwrap_or_default());
        vlan.dei_mut().set(self.dei.unwrap_or_default());
        vlan.vid_mut().set(self.vid.unwrap_or_default());
        vlan.eth_type_mut().set(self.eth_type.unwrap_or_default());
        vlan.payload_mut().copy_from_slice(&self.payload);

        vlan
    }
}

/// Create a Vlan layer with the given fields.
#[macro_export]
macro_rules! vlan {
    ($($field : ident : $value : expr),* $(,)?) => {
        $crate::layer::vlan::VlanBuilder::new()
            $(.$field($value))*
            .build()
    };
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn vlan_new_unchecked() {
        let data: [u8; 4] = [
            0x01, 0x23, // pcp: 0, dei: 0, vid: 0x123
            0x08, 0x00, // eth_type: 0x0800 (IPv4)
        ];

        let vlan = unsafe { Vlan::new_unchecked(data) };

        assert_eq!(vlan.pcp().get(), 0);
        assert_eq!(vlan.dei().get(), false);
        assert_eq!(vlan.vid().get(), 0x123);
        assert_eq!(vlan.eth_type().get(), EthType::Ipv4);
    }

    #[test]
    fn vlan_macro() {
        let vlan = vlan!(
            tci: 0x0123u16,
            eth_type: EthType::Ipv4,
            payload: [0x01, 0x02, 0x03, 0x04],
        );

        assert_eq!(vlan.pcp().get(), 0);
        assert_eq!(vlan.dei().get(), false);
        assert_eq!(vlan.vid().get(), 0x123);
        assert_eq!(vlan.eth_type().get(), EthType::Ipv4);
        assert_eq!(vlan.payload(), &[0x01, 0x02, 0x03, 0x04]);
    }
}
