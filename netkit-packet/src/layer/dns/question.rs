//! Dns Question

use crate::field_spec;
use crate::prelude::*;

use super::{class::DnsClass, rrtype::DnsRrType, DnsName};

/// Error type of DnsQuestion
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum DnsQuestionError {
    /// No root label found
    #[error("No root label found")]
    NoRootLabelFound,
}

/// DnsQuestion
///
/// The format of a question is as follows:
///
/// ```text
///   0  1  2  3  4  5  6  7
/// +--+--+--+--+--+--+--+--+----------~~~----------+
/// |                                         QNAME |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                         QTYPE |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                        QCLASS |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Clone, Debug)]
pub struct DnsQuestion<T> {
    data: T,
    name_len: usize,
}

field_spec!(QtypeSpec, DnsRrType, u16);
field_spec!(QclassSpec, DnsClass, u16);

impl<T> DnsQuestion<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new DnsQuestion from the given data
    pub fn new(data: T) -> Result<DnsQuestion<T>, DnsQuestionError> {
        // Find the length of the name by finding the first null byte
        let name_len = data
            .as_ref()
            .iter()
            .position(|&x| x == 0)
            .ok_or(DnsQuestionError::NoRootLabelFound)?;

        Ok(DnsQuestion { data, name_len })
    }

    /// Get the inner raw data
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the length of the DnsQuestion
    #[inline]
    pub const fn len(&self) -> usize {
        self.name_len + 4
    }

    /// Unimplemented: Make clippy happy :)
    #[inline]
    pub const fn is_empty(&self) -> bool {
        // Should DnsQuestion be `empty`?
        unimplemented!()
    }

    /// Get the question name
    #[inline]
    pub fn qname(&self) -> DnsName<&[u8]> {
        unsafe { DnsName::new_unchecked(&self.data.as_ref()[..=self.name_len]) }
    }

    /// Get the accessor of qtype
    #[inline]
    pub fn qtype(&self) -> &Field<QtypeSpec> {
        cast_from_bytes(&self.data.as_ref()[self.name_len + 1..self.name_len + 3])
    }

    /// Get the accessor of qclass
    #[inline]
    pub fn qclass(&self) -> &Field<QclassSpec> {
        cast_from_bytes(&self.data.as_ref()[self.name_len + 3..self.name_len + 5])
    }
}

impl<T> DnsQuestion<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable name
    #[inline]
    pub fn qname_mut(&mut self) -> DnsName<&mut [u8]> {
        unsafe { DnsName::new_unchecked(&mut self.data.as_mut()[..=self.name_len]) }
    }

    /// Get the mutable accessor of qtype
    #[inline]
    pub fn qtype_mut(&mut self) -> &mut Field<QtypeSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[self.name_len + 1..self.name_len + 3])
    }

    /// Get the mutable accessor of qclass
    #[inline]
    pub fn qclass_mut(&mut self) -> &mut Field<QclassSpec> {
        cast_from_bytes_mut(&mut self.data.as_mut()[self.name_len + 3..self.name_len + 5])
    }
}

/// Builder for DnsQuestion
#[derive(Clone, Debug, Default)]
pub struct DnsQuestionBuilder {
    qname: Option<String>,
    qtype: Option<DnsRrType>,
    qclass: Option<DnsClass>,
}

impl DnsQuestionBuilder {
    /// Create a new DnsQuestionBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the name
    pub fn qname(&mut self, name: impl Into<String>) -> &mut Self {
        self.qname = Some(name.into());
        self
    }

    /// Set the qtype
    pub fn qtype<T>(&mut self, qtype: T) -> &mut Self
    where
        T: TryInto<DnsRrType>,
        <T as TryInto<DnsRrType>>::Error: core::fmt::Debug,
    {
        self.qtype = Some(qtype.try_into().unwrap());
        self
    }

    /// Set the qclass
    pub fn qclass<T>(&mut self, qclass: T) -> &mut Self
    where
        T: TryInto<DnsClass>,
        <T as TryInto<DnsClass>>::Error: core::fmt::Debug,
    {
        self.qclass = Some(qclass.try_into().unwrap());
        self
    }

    /// Build the DnsQuestion
    pub fn build(&self) -> DnsQuestion<Vec<u8>> {
        let qname = DnsName::from(self.qname.as_deref().unwrap_or(""));
        let qtype = self.qtype.unwrap_or(DnsRrType::A);
        let qclass = self.qclass.unwrap_or(DnsClass::Internet);

        let mut data = qname.into_inner();
        let len = data.len();
        data.resize(data.len() + 4, 0);

        let mut question = DnsQuestion {
            data,
            name_len: len - 1,
        };

        question.qtype_mut().set(qtype);
        question.qclass_mut().set(qclass);

        question
    }
}

/// Create a DnsQuestion with the given fields.
#[macro_export]
macro_rules! dns_question {
    ($($field : ident : $value : expr),* $(,)?) => {
        $crate::layer::dns::question::DnsQuestionBuilder::new()
            $(.$field($value))*
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_question_new() {
        let data = b"\x03www\x06google\x03com\x00\x00\x01\x00\x01";
        let question = DnsQuestion::new(data).unwrap();

        assert_eq!(question.qname().to_string(), "www.google.com.");
        assert_eq!(question.qtype().get(), DnsRrType::A);
        assert_eq!(question.qclass().get(), DnsClass::Internet);

        let data = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01";
        let question = DnsQuestion::new(data).unwrap();

        assert_eq!(question.qname().to_string(), "www.example.com.");
        assert_eq!(question.qtype().get(), DnsRrType::A);
        assert_eq!(question.qclass().get(), DnsClass::Internet);
    }

    #[test]
    fn dns_question_macro() {
        let question = dns_question!(
            qname: "www.google.com",
            qtype: "A",
            qclass: "IN",
        );

        assert_eq!(question.qname().to_string(), "www.google.com.");
        assert_eq!(question.qtype().get(), DnsRrType::A);
        assert_eq!(question.qclass().get(), DnsClass::Internet);

        let question = dns_question!(
            qname: "www.example.com",
            qtype: "A",
            qclass: "IN"
        );

        assert_eq!(question.qname().to_string(), "www.example.com.");
        assert_eq!(question.qtype().get(), DnsRrType::A);
        assert_eq!(question.qclass().get(), DnsClass::Internet);
    }
}
