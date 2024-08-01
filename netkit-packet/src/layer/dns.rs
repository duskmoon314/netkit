//! Domain Name System (DNS) layer

use crate::{field_spec, prelude::*};

pub mod opcode;
pub use opcode::DnsOpCode;

pub mod rcode;
pub use rcode::DnsRCode;

pub mod label;
pub use label::DnsLabel;

pub mod name;
pub use name::DnsName;

pub mod question;
pub use question::DnsQuestion;

pub mod rrtype;
pub use rrtype::DnsRrType;

pub mod class;
pub use class::DnsClass;

/// Error type for Dns layer
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum DnsError {
    /// Invalid Dns length
    #[error("Invalid Dns length: Length {0} is less than 12")]
    InvalidLength(usize),
}

field_spec!(IdSpec, u16, u16);
field_spec!(QrSpec, bool, u8, 0x80, 7);
field_spec!(OpCodeSpec, DnsOpCode, u8, 0x78, 3);
field_spec!(AaSpec, bool, u8, 0x04, 2);
field_spec!(TcSpec, bool, u8, 0x02, 1);
field_spec!(RdSpec, bool, u8, 0x01, 0);
field_spec!(RaSpec, bool, u8, 0x80, 7);
field_spec!(ZSpec, u8, u8, 0x70, 4);
field_spec!(RCodeSpec, DnsRCode, u8, 0x0F, 0);
field_spec!(CountSpec, u16, u16);

/// Minimum length of a Dns header
pub const MIN_HEADER_LENGTH: usize = 12;

/// Domain Name System (DNS) layer
pub struct Dns<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Dns<T>
where
    T: AsRef<[u8]>,
{
    /// Field ranges of the ID: 0..2
    pub const FIELD_ID: core::ops::Range<usize> = 0..2;
    /// Field ranges of the QR: 2..3
    pub const FIELD_QR: core::ops::Range<usize> = 2..3;
    /// Field ranges of the OpCode: 2..3
    pub const FIELD_OPCODE: core::ops::Range<usize> = 2..3;
    /// Field ranges of the AA: 2..3
    pub const FIELD_AA: core::ops::Range<usize> = 2..3;
    /// Field ranges of the TC: 2..3
    pub const FIELD_TC: core::ops::Range<usize> = 2..3;
    /// Field ranges of the RD: 2..3
    pub const FIELD_RD: core::ops::Range<usize> = 2..3;
    /// Field ranges of the RA: 3..4
    pub const FIELD_RA: core::ops::Range<usize> = 3..4;
    /// Field ranges of the Z: 3..4
    pub const FIELD_Z: core::ops::Range<usize> = 3..4;
    /// Field ranges of the RCode: 3..4
    pub const FIELD_RCODE: core::ops::Range<usize> = 3..4;
    /// Field ranges of the QDCount: 4..6
    pub const FIELD_QDCOUNT: core::ops::Range<usize> = 4..6;
    /// Field ranges of the ANCount: 6..8
    pub const FIELD_ANCOUNT: core::ops::Range<usize> = 6..8;
    /// Field ranges of the NSCount: 8..10
    pub const FIELD_NSCOUNT: core::ops::Range<usize> = 8..10;
    /// Field ranges of the ARCount: 10..12
    pub const FIELD_ARCOUNT: core::ops::Range<usize> = 10..12;

    /// Create a new DNS layer without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid DNS packet.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the DNS layer
    pub fn validate(&self) -> Result<(), DnsError> {
        if self.data.as_ref().len() < 12 {
            return Err(DnsError::InvalidLength(self.data.as_ref().len()));
        }

        // TODO: validate count and rr, etc.

        Ok(())
    }

    /// Create a new Dns layer from raw data.
    #[inline]
    pub fn new(data: T) -> Result<Self, DnsError> {
        let res = unsafe { Self::new_unchecked(data) };
        res.validate()?;
        Ok(res)
    }

    /// Get the inner raw data
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the ID
    #[inline]
    pub fn id(&self) -> &Field<IdSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_ID])
    }

    /// Get the accessor of the QR
    #[inline]
    pub fn qr(&self) -> &Field<QrSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_QR])
    }

    /// Get the accessor of the OpCode
    #[inline]
    pub fn opcode(&self) -> &Field<OpCodeSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_OPCODE])
    }

    /// Get the accessor of the AA
    #[inline]
    pub fn aa(&self) -> &Field<AaSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_AA])
    }

    /// Get the accessor of the TC
    #[inline]
    pub fn tc(&self) -> &Field<TcSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_TC])
    }

    /// Get the accessor of the RD
    #[inline]
    pub fn rd(&self) -> &Field<RdSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_RD])
    }

    /// Get the accessor of the RA
    #[inline]
    pub fn ra(&self) -> &Field<RaSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_RA])
    }

    /// Get the accessor of the Z
    #[inline]
    pub fn z(&self) -> &Field<ZSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_Z])
    }

    /// Get the accessor of the RCode
    #[inline]
    pub fn rcode(&self) -> &Field<RCodeSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_RCODE])
    }

    /// Get the accessor of the QDCount
    #[inline]
    pub fn qdcount(&self) -> &Field<CountSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_QDCOUNT])
    }

    /// Get the accessor of the ANCount
    #[inline]
    pub fn ancount(&self) -> &Field<CountSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_ANCOUNT])
    }

    /// Get the accessor of the NSCount
    #[inline]
    pub fn nscount(&self) -> &Field<CountSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_NSCOUNT])
    }

    /// Get the accessor of the ARCount
    #[inline]
    pub fn arcount(&self) -> &Field<CountSpec> {
        cast_from_bytes(&self.data.as_ref()[Self::FIELD_ARCOUNT])
    }

    /// Get the iterator of the questions
    pub fn questions(&self) -> DnsQuestionIter<T> {
        DnsQuestionIter::from(self)
    }
}

impl<T> Dns<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the ID
    #[inline]
    pub fn id_mut(&mut self) -> &mut Field<IdSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_ID])
    }

    /// Get the mutable accessor of the QR
    #[inline]
    pub fn qr_mut(&mut self) -> &mut Field<QrSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_QR])
    }

    /// Get the mutable accessor of the OpCode
    #[inline]
    pub fn opcode_mut(&mut self) -> &mut Field<OpCodeSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_OPCODE])
    }

    /// Get the mutable accessor of the AA
    #[inline]
    pub fn aa_mut(&mut self) -> &mut Field<AaSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_AA])
    }

    /// Get the mutable accessor of the TC
    #[inline]
    pub fn tc_mut(&mut self) -> &mut Field<TcSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_TC])
    }

    /// Get the mutable accessor of the RD
    #[inline]
    pub fn rd_mut(&mut self) -> &mut Field<RdSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_RD])
    }

    /// Get the mutable accessor of the RA
    #[inline]
    pub fn ra_mut(&mut self) -> &mut Field<RaSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_RA])
    }

    /// Get the mutable accessor of the Z
    #[inline]
    pub fn z_mut(&mut self) -> &mut Field<ZSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_Z])
    }

    /// Get the mutable accessor of the RCode
    #[inline]
    pub fn rcode_mut(&mut self) -> &mut Field<RCodeSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_RCODE])
    }

    /// Get the mutable accessor of the QDCount
    #[inline]
    pub fn qdcount_mut(&mut self) -> &mut Field<CountSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_QDCOUNT])
    }

    /// Get the mutable accessor of the ANCount
    #[inline]
    pub fn ancount_mut(&mut self) -> &mut Field<CountSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_ANCOUNT])
    }

    /// Get the mutable accessor of the NSCount
    #[inline]
    pub fn nscount_mut(&mut self) -> &mut Field<CountSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_NSCOUNT])
    }

    /// Get the mutable accessor of the ARCount
    #[inline]
    pub fn arcount_mut(&mut self) -> &mut Field<CountSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[Self::FIELD_ARCOUNT])
    }
}

layer_impl!(Dns);

/// Iterator for [`DnsQuestion`]
pub struct DnsQuestionIter<'a, T>
where
    T: AsRef<[u8]>,
{
    dns: &'a Dns<T>,
    offset: usize,
    current: usize,
}

impl<'a, T> From<&'a Dns<T>> for DnsQuestionIter<'a, T>
where
    T: AsRef<[u8]>,
{
    fn from(dns: &'a Dns<T>) -> Self {
        Self {
            dns,
            offset: MIN_HEADER_LENGTH,
            current: 0,
        }
    }
}

impl<'a, T> Iterator for DnsQuestionIter<'a, T>
where
    T: AsRef<[u8]>,
{
    type Item = DnsQuestion<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.dns.inner().as_ref().len()
            || self.current >= self.dns.qdcount().get() as usize
        {
            return None;
        }

        let question = DnsQuestion::new(&self.dns.inner().as_ref()[self.offset..]).ok()?;
        self.offset += question.len();
        self.current += 1;

        Some(question)
    }
}

/// Builder for [`Dns`]
#[derive(Clone, Debug, Default)]
pub struct DnsBuilder {
    id: Option<u16>,
    qr: Option<bool>,
    opcode: Option<DnsOpCode>,
    aa: Option<bool>,
    tc: Option<bool>,
    rd: Option<bool>,
    ra: Option<bool>,
    z: Option<u8>,
    rcode: Option<DnsRCode>,
    qdcount: Option<u16>,
    ancount: Option<u16>,
    nscount: Option<u16>,
    arcount: Option<u16>,
    questions: Vec<DnsQuestion<Vec<u8>>>,
}

impl DnsBuilder {
    /// Create a new Dns builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the ID
    pub fn id(&mut self, id: impl Into<u16>) -> &mut Self {
        self.id = Some(id.into());
        self
    }

    /// Set the QR
    pub fn qr(&mut self, qr: impl Into<bool>) -> &mut Self {
        self.qr = Some(qr.into());
        self
    }

    /// Set the OpCode
    pub fn opcode(&mut self, opcode: impl Into<DnsOpCode>) -> &mut Self {
        self.opcode = Some(opcode.into());
        self
    }

    /// Set the AA
    pub fn aa(&mut self, aa: impl Into<bool>) -> &mut Self {
        self.aa = Some(aa.into());
        self
    }

    /// Set the TC
    pub fn tc(&mut self, tc: impl Into<bool>) -> &mut Self {
        self.tc = Some(tc.into());
        self
    }

    /// Set the RD
    pub fn rd(&mut self, rd: impl Into<bool>) -> &mut Self {
        self.rd = Some(rd.into());
        self
    }

    /// Set the RA
    pub fn ra(&mut self, ra: impl Into<bool>) -> &mut Self {
        self.ra = Some(ra.into());
        self
    }

    /// Set the Z
    pub fn z(&mut self, z: impl Into<u8>) -> &mut Self {
        self.z = Some(z.into());
        self
    }

    /// Set the RCode
    pub fn rcode(&mut self, rcode: impl Into<DnsRCode>) -> &mut Self {
        self.rcode = Some(rcode.into());
        self
    }

    /// Set the QDCount
    pub fn qdcount(&mut self, qdcount: impl Into<u16>) -> &mut Self {
        self.qdcount = Some(qdcount.into());
        self
    }

    /// Set the ANCount
    pub fn ancount(&mut self, ancount: impl Into<u16>) -> &mut Self {
        self.ancount = Some(ancount.into());
        self
    }

    /// Set the NSCount
    pub fn nscount(&mut self, nscount: impl Into<u16>) -> &mut Self {
        self.nscount = Some(nscount.into());
        self
    }

    /// Set the ARCount
    pub fn arcount(&mut self, arcount: impl Into<u16>) -> &mut Self {
        self.arcount = Some(arcount.into());
        self
    }

    /// Set the questions
    pub fn questions(&mut self, question: impl Into<DnsQuestion<Vec<u8>>>) -> &mut Self {
        self.questions.push(question.into());
        self
    }

    /// Build the Dns layer
    pub fn build(&self) -> Dns<Vec<u8>> {
        let mut dns = unsafe { Dns::new_unchecked(vec![0; 12]) };

        dns.id_mut().set(self.id.unwrap_or(0));
        dns.qr_mut().set(self.qr.unwrap_or(false));
        dns.opcode_mut()
            .set(self.opcode.unwrap_or(DnsOpCode::Query));
        dns.aa_mut().set(self.aa.unwrap_or(false));
        dns.tc_mut().set(self.tc.unwrap_or(false));
        dns.rd_mut().set(self.rd.unwrap_or(false));
        dns.ra_mut().set(self.ra.unwrap_or(false));
        dns.z_mut().set(self.z.unwrap_or(0));
        dns.rcode_mut().set(self.rcode.unwrap_or(DnsRCode::NoError));
        dns.ancount_mut().set(self.ancount.unwrap_or(0));
        dns.nscount_mut().set(self.nscount.unwrap_or(0));
        dns.arcount_mut().set(self.arcount.unwrap_or(0));

        let qdcount = self.qdcount.unwrap_or(self.questions.len() as u16);
        dns.qdcount_mut().set(qdcount);
        for question in self.questions.iter().take(qdcount as usize) {
            dns.inner_mut().extend_from_slice(question.inner());
        }

        dns
    }
}

/// Create a new Dns layer with the given fields.
#[macro_export]
macro_rules! dns {
    ($($field : ident : $value : expr),* $(,)?) => {{
        $crate::layer::dns::DnsBuilder::new()
            $(.$field($value))*
            .build()
    }};
}

#[cfg(test)]
mod tests {
    use crate::dns_question;

    use super::*;

    #[test]
    fn dns_new_unchecked() {
        let data: [u8; 29] = [
            0x01, 0x02, // id
            0x00, // qr, opcode, aa, tc, rd
            0x00, // ra, z, rcode
            0x00, 0x01, // qd_count
            0x00, 0x00, // an_count
            0x00, 0x00, // ns_count
            0x00, 0x00, // ar_count
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            0x00, // qname example.com
            0x00, 0x01, // qtype A
            0x00, 0x01, // qclass IN
        ];

        let dns = unsafe { Dns::new_unchecked(data) };

        assert_eq!(dns.id().get(), 0x0102);
        assert_eq!(dns.qr().get(), false);
        assert_eq!(dns.opcode().get(), DnsOpCode::Query);
        assert_eq!(dns.aa().get(), false);
        assert_eq!(dns.tc().get(), false);
        assert_eq!(dns.rd().get(), false);
        assert_eq!(dns.ra().get(), false);
        assert_eq!(dns.z().get(), 0);
        assert_eq!(dns.rcode().get(), DnsRCode::NoError);
        assert_eq!(dns.qdcount().get(), 1);
        assert_eq!(dns.ancount().get(), 0);
        assert_eq!(dns.nscount().get(), 0);
        assert_eq!(dns.arcount().get(), 0);

        let questions = dns.questions().collect::<Vec<_>>();
        assert_eq!(questions.len(), 1);

        assert_eq!(questions[0].qname(), "example.com");
        assert_eq!(questions[0].qtype().get(), DnsRrType::A);
        assert_eq!(questions[0].qclass().get(), DnsClass::Internet);
    }

    #[test]
    fn dns_macro() {
        let dns = dns!(
            id: 0x0102u16,
            rd: true,
            questions: dns_question!(
                qname: "www.example.com",
                qtype: "A",
                qclass: "IN"
            )

        );

        assert_eq!(
            dns.inner(),
            &[
                0x01, 0x02, // id
                0x01, // qr, opcode, aa, tc, rd
                0x00, // ra, z, rcode
                0x00, 0x01, // qd_count
                0x00, 0x00, // an_count
                0x00, 0x00, // ns_count
                0x00, 0x00, // ar_count
                0x03, 0x77, 0x77, 0x77, // qname label[0] www
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // qname label[1] example
                0x03, 0x63, 0x6f, 0x6d, 0x00, // qname label[2] com
                0x00, 0x01, // qtype A
                0x00, 0x01, // qclass IN
            ]
        )
    }
}
