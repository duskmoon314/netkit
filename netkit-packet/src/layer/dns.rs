//! Domain Name System (DNS) layer

use std::cell::Cell;

use crate::{field_spec, prelude::*};

pub mod opcode;
pub use opcode::DnsOpCode;

pub mod rcode;
pub use rcode::DnsRCode;

pub mod label;
pub use label::DnsLabel;

pub mod name;
pub use name::{DnsName, DnsNameError};

pub mod question;
pub use question::DnsQuestion;

pub mod rrtype;
pub use rrtype::DnsRrType;

pub mod class;
pub use class::DnsClass;

pub mod rr;
pub use rr::DnsResourceRecord;

/// Error type for Dns layer
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum DnsError {
    /// Invalid Dns length
    #[error("Invalid Dns length: Length {0} is less than 12")]
    InvalidLength(usize),
    /// Invalid question
    #[error("Invalid question: {0}")]
    InvalidQuestion(String),
    /// Invalid resource record
    #[error("Invalid resource record: {0}")]
    InvalidResourceRecord(String),
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

/// Cached section offsets for efficient access
#[derive(Debug, Clone, Copy)]
struct SectionOffsets {
    questions_end: usize,
    answers_end: usize,
    authorities_end: usize,
}

/// Domain Name System (DNS) layer
pub struct Dns<T>
where
    T: AsRef<[u8]>,
{
    data: T,
    /// Cached offsets, calculated on first access
    offsets: Cell<Option<SectionOffsets>>,
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
        Self {
            data,
            offsets: Cell::new(None),
        }
    }

    /// Validate the DNS layer
    pub fn validate(&self) -> Result<(), DnsError> {
        if self.data.as_ref().len() < 12 {
            return Err(DnsError::InvalidLength(self.data.as_ref().len()));
        }

        // Validate questions section by attempting to parse all questions
        let qd_count = self.qdcount().get() as usize;
        let parsed_questions = self.questions().count();
        if parsed_questions < qd_count {
            return Err(DnsError::InvalidQuestion(format!(
                "Expected {} questions, only parsed {}",
                qd_count, parsed_questions
            )));
        }

        // Validate answer section
        let an_count = self.ancount().get() as usize;
        let parsed_answers = self.answers().count();
        if parsed_answers < an_count {
            return Err(DnsError::InvalidResourceRecord(format!(
                "Expected {} answers, only parsed {}",
                an_count, parsed_answers
            )));
        }

        // Validate authority section
        let ns_count = self.nscount().get() as usize;
        let parsed_authorities = self.authorities().count();
        if parsed_authorities < ns_count {
            return Err(DnsError::InvalidResourceRecord(format!(
                "Expected {} authorities, only parsed {}",
                ns_count, parsed_authorities
            )));
        }

        // Validate additional section
        let ar_count = self.arcount().get() as usize;
        let parsed_additionals = self.additionals().count();
        if parsed_additionals < ar_count {
            return Err(DnsError::InvalidResourceRecord(format!(
                "Expected {} additionals, only parsed {}",
                ar_count, parsed_additionals
            )));
        }

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
    pub fn id(&self) -> FieldRef<'_, IdSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ID])
    }

    /// Get the accessor of the QR
    #[inline]
    pub fn qr(&self) -> FieldRef<'_, QrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_QR])
    }

    /// Get the accessor of the OpCode
    #[inline]
    pub fn opcode(&self) -> FieldRef<'_, OpCodeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_OPCODE])
    }

    /// Get the accessor of the AA
    #[inline]
    pub fn aa(&self) -> FieldRef<'_, AaSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_AA])
    }

    /// Get the accessor of the TC
    #[inline]
    pub fn tc(&self) -> FieldRef<'_, TcSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TC])
    }

    /// Get the accessor of the RD
    #[inline]
    pub fn rd(&self) -> FieldRef<'_, RdSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RD])
    }

    /// Get the accessor of the RA
    #[inline]
    pub fn ra(&self) -> FieldRef<'_, RaSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RA])
    }

    /// Get the accessor of the Z
    #[inline]
    pub fn z(&self) -> FieldRef<'_, ZSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_Z])
    }

    /// Get the accessor of the RCode
    #[inline]
    pub fn rcode(&self) -> FieldRef<'_, RCodeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RCODE])
    }

    /// Get the accessor of the QDCount
    #[inline]
    pub fn qdcount(&self) -> FieldRef<'_, CountSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_QDCOUNT])
    }

    /// Get the accessor of the ANCount
    #[inline]
    pub fn ancount(&self) -> FieldRef<'_, CountSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ANCOUNT])
    }

    /// Get the accessor of the NSCount
    #[inline]
    pub fn nscount(&self) -> FieldRef<'_, CountSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_NSCOUNT])
    }

    /// Get the accessor of the ARCount
    #[inline]
    pub fn arcount(&self) -> FieldRef<'_, CountSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ARCOUNT])
    }

    /// Get the iterator of the questions
    pub fn questions(&self) -> DnsQuestionIter<'_, T> {
        DnsQuestionIter::from(self)
    }

    /// Calculate all section offsets in a single pass and cache them
    fn calculate_offsets(&self) -> SectionOffsets {
        if let Some(cached) = self.offsets.get() {
            return cached;
        }

        let mut offset = MIN_HEADER_LENGTH;
        let data = self.data.as_ref();

        // Parse questions section
        let qdcount = self.qdcount().get() as usize;
        for _ in 0..qdcount {
            if offset >= data.len() {
                break;
            }
            if let Ok(question) = DnsQuestion::new(&data[offset..]) {
                offset += question.len();
            } else {
                break;
            }
        }
        let questions_end = offset;

        // Parse answers section
        let ancount = self.ancount().get() as usize;
        for _ in 0..ancount {
            if offset >= data.len() {
                break;
            }
            if let Ok(rr) = DnsResourceRecord::new(&data[offset..]) {
                offset += rr.len();
            } else {
                break;
            }
        }
        let answers_end = offset;

        // Parse authorities section
        let nscount = self.nscount().get() as usize;
        for _ in 0..nscount {
            if offset >= data.len() {
                break;
            }
            if let Ok(rr) = DnsResourceRecord::new(&data[offset..]) {
                offset += rr.len();
            } else {
                break;
            }
        }
        let authorities_end = offset;

        let offsets = SectionOffsets {
            questions_end,
            answers_end,
            authorities_end,
        };
        self.offsets.set(Some(offsets));
        offsets
    }

    /// Calculate offset to skip questions section
    fn questions_end_offset(&self) -> usize {
        self.calculate_offsets().questions_end
    }

    /// Calculate offset to skip questions + answers sections
    fn answers_end_offset(&self) -> usize {
        self.calculate_offsets().answers_end
    }

    /// Calculate offset to skip questions + answers + authorities sections
    fn authorities_end_offset(&self) -> usize {
        self.calculate_offsets().authorities_end
    }

    /// Get the iterator of the answer records
    pub fn answers(&self) -> DnsRrIter<'_, T> {
        let offset = self.questions_end_offset();
        DnsRrIter::new(self, offset, self.ancount().get() as usize)
    }

    /// Get the iterator of the authority records
    pub fn authorities(&self) -> DnsRrIter<'_, T> {
        let offset = self.answers_end_offset();
        DnsRrIter::new(self, offset, self.nscount().get() as usize)
    }

    /// Get the iterator of the additional records
    pub fn additionals(&self) -> DnsRrIter<'_, T> {
        let offset = self.authorities_end_offset();
        DnsRrIter::new(self, offset, self.arcount().get() as usize)
    }

    /// Resolve a DNS name with compression pointers to a string
    ///
    /// This is the high-level method for resolving DNS names within this packet.
    /// It handles compression pointers and returns the fully qualified domain name.
    ///
    /// # Arguments
    ///
    /// * `name` - The DNS name to resolve (from questions, answers, etc.)
    ///
    /// # Returns
    ///
    /// A string containing the fully qualified domain name with trailing dot (e.g., "example.com.")
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let dns = Dns::new(&packet_data)?;
    /// for answer in dns.answers() {
    ///     let name = dns.resolve_name(&answer.name())?;
    ///     println!("Name: {}", name);
    /// }
    /// ```
    pub fn resolve_name<N: AsRef<[u8]>>(&self, name: &DnsName<N>) -> Result<String, DnsNameError> {
        name.resolve(self.data.as_ref())
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
    pub fn id_mut(&mut self) -> FieldMut<'_, IdSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ID])
    }

    /// Get the mutable accessor of the QR
    #[inline]
    pub fn qr_mut(&mut self) -> FieldMut<'_, QrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_QR])
    }

    /// Get the mutable accessor of the OpCode
    #[inline]
    pub fn opcode_mut(&mut self) -> FieldMut<'_, OpCodeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_OPCODE])
    }

    /// Get the mutable accessor of the AA
    #[inline]
    pub fn aa_mut(&mut self) -> FieldMut<'_, AaSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_AA])
    }

    /// Get the mutable accessor of the TC
    #[inline]
    pub fn tc_mut(&mut self) -> FieldMut<'_, TcSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TC])
    }

    /// Get the mutable accessor of the RD
    #[inline]
    pub fn rd_mut(&mut self) -> FieldMut<'_, RdSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_RD])
    }

    /// Get the mutable accessor of the RA
    #[inline]
    pub fn ra_mut(&mut self) -> FieldMut<'_, RaSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_RA])
    }

    /// Get the mutable accessor of the Z
    #[inline]
    pub fn z_mut(&mut self) -> FieldMut<'_, ZSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_Z])
    }

    /// Get the mutable accessor of the RCode
    #[inline]
    pub fn rcode_mut(&mut self) -> FieldMut<'_, RCodeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_RCODE])
    }

    /// Get the mutable accessor of the QDCount
    #[inline]
    pub fn qdcount_mut(&mut self) -> FieldMut<'_, CountSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_QDCOUNT])
    }

    /// Get the mutable accessor of the ANCount
    #[inline]
    pub fn ancount_mut(&mut self) -> FieldMut<'_, CountSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ANCOUNT])
    }

    /// Get the mutable accessor of the NSCount
    #[inline]
    pub fn nscount_mut(&mut self) -> FieldMut<'_, CountSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_NSCOUNT])
    }

    /// Get the mutable accessor of the ARCount
    #[inline]
    pub fn arcount_mut(&mut self) -> FieldMut<'_, CountSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ARCOUNT])
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

/// Iterator for [`DnsResourceRecord`]
pub struct DnsRrIter<'a, T>
where
    T: AsRef<[u8]>,
{
    dns: &'a Dns<T>,
    offset: usize,
    current: usize,
    total: usize,
}

impl<'a, T> DnsRrIter<'a, T>
where
    T: AsRef<[u8]>,
{
    /// Create an iterator starting at the given offset with the given count
    fn new(dns: &'a Dns<T>, offset: usize, count: usize) -> Self {
        Self {
            dns,
            offset,
            current: 0,
            total: count,
        }
    }
}

impl<'a, T> Iterator for DnsRrIter<'a, T>
where
    T: AsRef<[u8]>,
{
    type Item = DnsResourceRecord<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.dns.inner().as_ref().len() || self.current >= self.total {
            return None;
        }

        let rr = DnsResourceRecord::new(&self.dns.inner().as_ref()[self.offset..]).ok()?;
        self.offset += rr.len();
        self.current += 1;

        Some(rr)
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

    #[test]
    fn dns_response_with_answers() {
        // DNS response for "example.com" A query with one answer
        // Header: ID=0x1234, QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
        //         QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        // Question: example.com A IN
        // Answer: example.com A IN TTL=3600 93.184.216.34
        let data = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Answer section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x0E, 0x10, // TTL = 3600
            0x00, 0x04, // RDLENGTH = 4
            93, 184, 216, 34, // RDATA = 93.184.216.34
        ];

        let dns = Dns::new(&data).unwrap();

        // Check header
        assert_eq!(dns.id().get(), 0x1234);
        assert_eq!(dns.qr().get(), true);
        assert_eq!(dns.rd().get(), true);
        assert_eq!(dns.ra().get(), true);
        assert_eq!(dns.qdcount().get(), 1);
        assert_eq!(dns.ancount().get(), 1);
        assert_eq!(dns.nscount().get(), 0);
        assert_eq!(dns.arcount().get(), 0);

        // Check question
        let questions: Vec<_> = dns.questions().collect();
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].qname(), "example.com");
        assert_eq!(questions[0].qtype().get(), DnsRrType::A);
        assert_eq!(questions[0].qclass().get(), DnsClass::Internet);

        // Check answer
        let answers: Vec<_> = dns.answers().collect();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name(), "example.com");
        assert_eq!(answers[0].rrtype().get(), DnsRrType::A);
        assert_eq!(answers[0].class().get(), DnsClass::Internet);
        assert_eq!(answers[0].ttl().get(), 3600);
        assert_eq!(answers[0].rdlength().get(), 4);
        assert_eq!(answers[0].rdata(), &[93, 184, 216, 34]);
    }

    #[test]
    fn dns_response_with_compression() {
        // DNS response using compression pointers
        // Question: example.com A IN
        // Answer: example.com A IN TTL=300 192.0.2.1 (using pointer to question name)
        let data = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question section (starts at offset 12)
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Answer section
            0xC0, 0x0C, // Compression pointer to offset 12 (question name)
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x01, 0x2C, // TTL = 300
            0x00, 0x04, // RDLENGTH = 4
            192, 0, 2, 1, // RDATA = 192.0.2.1
        ];

        let dns = Dns::new(&data).unwrap();

        // Check answer with compression pointer
        let answers: Vec<_> = dns.answers().collect();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].rrtype().get(), DnsRrType::A);
        assert_eq!(answers[0].class().get(), DnsClass::Internet);
        assert_eq!(answers[0].ttl().get(), 300);
        assert_eq!(answers[0].rdlength().get(), 4);
        assert_eq!(answers[0].rdata(), &[192, 0, 2, 1]);
        // The name is a compression pointer, shown as PTR in display
        assert_eq!(answers[0].name().to_string(), "PTR(12)");
    }

    #[test]
    fn dns_response_multiple_sections() {
        // DNS response with question, answer, authority, and additional sections
        let mut data = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x01, // NSCOUNT = 1
            0x00, 0x01, // ARCOUNT = 1
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // A
            0x00, 0x01, // IN
        ];

        // Answer: example.com A IN 3600 93.184.216.34
        data.extend_from_slice(&[
            0xC0, 0x0C, // Pointer to question
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x0E, 0x10, // TTL=3600
            0x00, 0x04, // RDLENGTH=4
            93, 184, 216, 34,
        ]);

        // Authority: example.com NS IN 3600 ns.example.com
        data.extend_from_slice(&[
            0xC0, 0x0C, // Pointer to question
            0x00, 0x02, // NS
            0x00, 0x01, // IN
            0x00, 0x00, 0x0E, 0x10, // TTL=3600
            0x00, 0x10, // RDLENGTH=16
            0x02, b'n', b's', // ns label
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]);

        // Additional: ns.example.com A IN 3600 192.0.2.53
        data.extend_from_slice(&[
            0x02, b'n', b's', 0xC0, 0x0C, // Pointer to "example.com" in question
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x0E, 0x10, // TTL=3600
            0x00, 0x04, // RDLENGTH=4
            192, 0, 2, 53,
        ]);

        let dns = Dns::new(&data).unwrap();

        // Check counts
        assert_eq!(dns.qdcount().get(), 1);
        assert_eq!(dns.ancount().get(), 1);
        assert_eq!(dns.nscount().get(), 1);
        assert_eq!(dns.arcount().get(), 1);

        // Check all sections can be iterated
        assert_eq!(dns.questions().count(), 1);
        assert_eq!(dns.answers().count(), 1);
        assert_eq!(dns.authorities().count(), 1);
        assert_eq!(dns.additionals().count(), 1);

        // Verify answer section
        let answers: Vec<_> = dns.answers().collect();
        assert_eq!(answers[0].rrtype().get(), DnsRrType::A);
        assert_eq!(answers[0].rdata(), &[93, 184, 216, 34]);

        // Verify authority section
        let authorities: Vec<_> = dns.authorities().collect();
        assert_eq!(authorities[0].rrtype().get(), DnsRrType::NS);
        assert_eq!(authorities[0].rdlength().get(), 16);

        // Verify additional section
        let additionals: Vec<_> = dns.additionals().collect();
        assert_eq!(additionals[0].rrtype().get(), DnsRrType::A);
        assert_eq!(additionals[0].rdata(), &[192, 0, 2, 53]);
    }

    #[test]
    fn dns_resolved_name_with_compression() {
        // DNS response using compression - test resolved_name() method
        let data = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x02, // ANCOUNT = 2
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question section (starts at offset 12)
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // A
            0x00, 0x01, // IN
            // Answer 1: example.com A (using pointer to question)
            0xC0, 0x0C, // Compression pointer to offset 12
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x0E, 0x10, // TTL=3600
            0x00, 0x04, // RDLENGTH=4
            93, 184, 216, 34, // 93.184.216.34
            // Answer 2: www.example.com A (partial compression)
            0x03, b'w', b'w', b'w', // "www" label
            0xC0, 0x0C, // Pointer to "example.com" at offset 12
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x0E, 0x10, // TTL=3600
            0x00, 0x04, // RDLENGTH=4
            93, 184, 216, 35, // 93.184.216.35
        ];

        let dns = Dns::new(&data).unwrap();

        let answers: Vec<_> = dns.answers().collect();
        assert_eq!(answers.len(), 2);

        // First answer: fully compressed name - use Dns::resolve_name()
        let name1 = dns.resolve_name(&answers[0].name()).unwrap();
        assert_eq!(name1, "example.com.");
        assert_eq!(answers[0].rdata(), &[93, 184, 216, 34]);

        // Second answer: partially compressed name - use Dns::resolve_name()
        let name2 = dns.resolve_name(&answers[1].name()).unwrap();
        assert_eq!(name2, "www.example.com.");
        assert_eq!(answers[1].rdata(), &[93, 184, 216, 35]);
    }

    #[test]
    fn dns_resolved_name_no_compression() {
        // Test resolved_name() with normal (non-compressed) names
        let data = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // A
            0x00, 0x01, // IN
            // Answer with full name (no compression)
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x0E, 0x10, // TTL=3600
            0x00, 0x04, // RDLENGTH=4
            192, 0, 2, 1,
        ];

        let dns = Dns::new(&data).unwrap();

        let answers: Vec<_> = dns.answers().collect();
        assert_eq!(answers.len(), 1);

        // Resolve using Dns::resolve_name()
        let name = dns.resolve_name(&answers[0].name()).unwrap();
        assert_eq!(name, "example.com.");
    }

    #[test]
    fn dns_resolve_name_question() {
        // Test resolving question names
        let data = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (query)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: www.example.com
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, // A
            0x00, 0x01, // IN
        ];

        let dns = Dns::new(&data).unwrap();

        let questions: Vec<_> = dns.questions().collect();
        assert_eq!(questions.len(), 1);

        // Resolve question name using Dns::resolve_name()
        let name = dns.resolve_name(&questions[0].qname()).unwrap();
        assert_eq!(name, "www.example.com.");
    }

    #[test]
    fn test_dns_validate_success() {
        // Create a valid DNS packet with all sections
        let data = vec![
            0x12, 0x34, // ID
            0x84, 0x00, // Flags (response, authoritative)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // A
            0x00, 0x01, // IN
            // Answer: example.com A 93.184.216.34
            0xC0, 0x0C, // Name (pointer to offset 12)
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0E, 0x10, // TTL
            0x00, 0x04, // RDLENGTH = 4
            93, 184, 216, 34, // IPv4 address
        ];

        let dns = Dns::new(&data).unwrap();
        assert!(dns.validate().is_ok());
    }

    #[test]
    fn test_dns_validate_truncated() {
        // Create a DNS packet that claims to have 2 questions but only has data for 1
        let data = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x02, // QDCOUNT = 2 (but only 1 will be parseable)
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question 1: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // A
            0x00, 0x01, // IN
                  // No second question - truncated
        ];

        // Dns::new() calls validate(), so this should fail
        let result = Dns::new(&data);
        assert!(result.is_err());

        // Also test that validate() can be called directly on unchecked
        let dns = unsafe { Dns::new_unchecked(&data) };
        assert!(dns.validate().is_err());
    }
}
