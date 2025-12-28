//! Dns Resource Record

use crate::field_spec;
use crate::prelude::*;

use super::{DnsClass, DnsName, DnsRrType};

/// Error type of DnsResourceRecord
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum DnsResourceRecordError {
    /// Truncated resource record
    #[error("Truncated resource record")]
    Truncated,
    /// Invalid compression pointer
    #[error("Invalid compression pointer")]
    InvalidCompressionPointer,
}

/// DnsResourceRecord
///
/// The format of a resource record is as follows:
///
/// ```text
///   0  1  2  3  4  5  6  7
/// +--+--+--+--+--+--+--+--+----------~~~----------+
/// |                                          NAME |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                          TYPE |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                         CLASS |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                           TTL |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                      RDLENGTH |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                         RDATA |
/// +--+--+--+--+--+--+--+--+----------~~~----------+
/// ```
#[derive(Clone, Debug)]
pub struct DnsResourceRecord<T> {
    data: T,
    name_len: usize,
}

field_spec!(RrTypeSpec, DnsRrType, u16);
field_spec!(RrClassSpec, DnsClass, u16);
field_spec!(TtlSpec, u32, u32);
field_spec!(RdLengthSpec, u16, u16);

impl<T> DnsResourceRecord<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new DnsResourceRecord from the given data
    pub fn new(data: T) -> Result<DnsResourceRecord<T>, DnsResourceRecordError> {
        let bytes = data.as_ref();

        if bytes.is_empty() {
            return Err(DnsResourceRecordError::Truncated);
        }

        // Find the length of the name
        // Names can be: normal labels ending in 0, or a compression pointer (2 bytes starting with 0xC0)
        let mut pos = 0;
        let name_len;

        loop {
            if pos >= bytes.len() {
                return Err(DnsResourceRecordError::Truncated);
            }

            let len = bytes[pos];

            // Check if this is a compression pointer (top 2 bits are 11)
            if (len & 0xC0) == 0xC0 {
                // Compression pointer is 2 bytes
                if pos + 1 >= bytes.len() {
                    return Err(DnsResourceRecordError::InvalidCompressionPointer);
                }
                name_len = pos + 2;
                break;
            }

            // Check for root label (end of name)
            if len == 0 {
                name_len = pos + 1;
                break;
            }

            // Normal label: skip length byte + label bytes
            pos += 1 + len as usize;
        }

        // Ensure we have enough bytes for TYPE + CLASS + TTL + RDLENGTH
        if bytes.len() < name_len + 10 {
            return Err(DnsResourceRecordError::Truncated);
        }

        // Check that RDLENGTH doesn't overflow
        let rdlength_offset = name_len + 8;
        let rdlength =
            u16::from_be_bytes([bytes[rdlength_offset], bytes[rdlength_offset + 1]]) as usize;

        if bytes.len() < name_len + 10 + rdlength {
            return Err(DnsResourceRecordError::Truncated);
        }

        Ok(DnsResourceRecord { data, name_len })
    }

    /// Get the inner raw data
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the total length of the DnsResourceRecord
    #[inline]
    pub fn len(&self) -> usize {
        let rdlength = self.rdlength().get() as usize;
        self.name_len + 10 + rdlength
    }

    /// Unimplemented: Make clippy happy :)
    #[inline]
    pub const fn is_empty(&self) -> bool {
        // Should DnsResourceRecord be `empty`?
        unimplemented!()
    }

    /// Get the resource record name
    #[inline]
    pub fn name(&self) -> DnsName<&[u8]> {
        unsafe { DnsName::new_unchecked(&self.data.as_ref()[..self.name_len]) }
    }

    /// Get the accessor of rrtype
    #[inline]
    pub fn rrtype(&self) -> FieldRef<'_, RrTypeSpec> {
        FieldRef::new(&self.data.as_ref()[self.name_len..self.name_len + 2])
    }

    /// Get the accessor of class
    #[inline]
    pub fn class(&self) -> FieldRef<'_, RrClassSpec> {
        FieldRef::new(&self.data.as_ref()[self.name_len + 2..self.name_len + 4])
    }

    /// Get the accessor of TTL
    #[inline]
    pub fn ttl(&self) -> FieldRef<'_, TtlSpec> {
        FieldRef::new(&self.data.as_ref()[self.name_len + 4..self.name_len + 8])
    }

    /// Get the accessor of RDLENGTH
    #[inline]
    pub fn rdlength(&self) -> FieldRef<'_, RdLengthSpec> {
        FieldRef::new(&self.data.as_ref()[self.name_len + 8..self.name_len + 10])
    }

    /// Get the RDATA as a slice
    #[inline]
    pub fn rdata(&self) -> &[u8] {
        let rdlength = self.rdlength().get() as usize;
        &self.data.as_ref()[self.name_len + 10..self.name_len + 10 + rdlength]
    }
}

impl<T> DnsResourceRecord<T>
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
    pub fn name_mut(&mut self) -> DnsName<&mut [u8]> {
        unsafe { DnsName::new_unchecked(&mut self.data.as_mut()[..self.name_len]) }
    }

    /// Get the mutable accessor of rrtype
    #[inline]
    pub fn rrtype_mut(&mut self) -> FieldMut<'_, RrTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[self.name_len..self.name_len + 2])
    }

    /// Get the mutable accessor of class
    #[inline]
    pub fn class_mut(&mut self) -> FieldMut<'_, RrClassSpec> {
        FieldMut::new(&mut self.data.as_mut()[self.name_len + 2..self.name_len + 4])
    }

    /// Get the mutable accessor of TTL
    #[inline]
    pub fn ttl_mut(&mut self) -> FieldMut<'_, TtlSpec> {
        FieldMut::new(&mut self.data.as_mut()[self.name_len + 4..self.name_len + 8])
    }

    /// Get the mutable accessor of RDLENGTH
    #[inline]
    pub fn rdlength_mut(&mut self) -> FieldMut<'_, RdLengthSpec> {
        FieldMut::new(&mut self.data.as_mut()[self.name_len + 8..self.name_len + 10])
    }

    /// Get the mutable RDATA as a slice
    #[inline]
    pub fn rdata_mut(&mut self) -> &mut [u8] {
        let rdlength = self.rdlength().get() as usize;
        &mut self.data.as_mut()[self.name_len + 10..self.name_len + 10 + rdlength]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_rr_new_with_normal_name() {
        // A record for "example.com" -> 93.184.216.34
        // NAME: \x07example\x03com\x00 (13 bytes)
        // TYPE: 0x0001 (A)
        // CLASS: 0x0001 (IN)
        // TTL: 0x00000E10 (3600)
        // RDLENGTH: 0x0004 (4)
        // RDATA: 93.184.216.34
        let data =
            b"\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x0E\x10\x00\x04\x5D\xB8\xD8\x22";
        let rr = DnsResourceRecord::new(data).unwrap();

        assert_eq!(rr.name().to_string(), "example.com.");
        assert_eq!(rr.rrtype().get(), DnsRrType::A);
        assert_eq!(rr.class().get(), DnsClass::Internet);
        assert_eq!(rr.ttl().get(), 3600);
        assert_eq!(rr.rdlength().get(), 4);
        assert_eq!(rr.rdata(), &[93, 184, 216, 34]);
        assert_eq!(rr.len(), 13 + 10 + 4);
    }

    #[test]
    fn dns_rr_new_with_compression_pointer() {
        // Name with compression pointer: \xC0\x0C (pointer to offset 12)
        // TYPE: 0x0001 (A)
        // CLASS: 0x0001 (IN)
        // TTL: 0x00000E10 (3600)
        // RDLENGTH: 0x0004 (4)
        // RDATA: 192.168.1.1
        let data = b"\xC0\x0C\x00\x01\x00\x01\x00\x00\x0E\x10\x00\x04\xC0\xA8\x01\x01";
        let rr = DnsResourceRecord::new(data).unwrap();

        assert_eq!(rr.rrtype().get(), DnsRrType::A);
        assert_eq!(rr.class().get(), DnsClass::Internet);
        assert_eq!(rr.ttl().get(), 3600);
        assert_eq!(rr.rdlength().get(), 4);
        assert_eq!(rr.rdata(), &[192, 168, 1, 1]);
        assert_eq!(rr.len(), 2 + 10 + 4);
    }

    #[test]
    fn dns_rr_truncated() {
        // Too short - only name
        let data = b"\x07example\x03com\x00";
        assert!(DnsResourceRecord::new(data).is_err());

        // Missing RDATA
        let data = b"\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x0E\x10\x00\x04";
        assert!(DnsResourceRecord::new(data).is_err());
    }

    #[test]
    fn dns_rr_aaaa_record() {
        // AAAA record for "example.com" -> 2606:2800:220:1:248:1893:25c8:1946
        let data = b"\x07example\x03com\x00\x00\x1C\x00\x01\x00\x00\x0E\x10\x00\x10\
                     \x26\x06\x28\x00\x02\x20\x00\x01\x02\x48\x18\x93\x25\xC8\x19\x46";
        let rr = DnsResourceRecord::new(data).unwrap();

        assert_eq!(rr.name().to_string(), "example.com.");
        assert_eq!(rr.rrtype().get(), DnsRrType::AAAA);
        assert_eq!(rr.class().get(), DnsClass::Internet);
        assert_eq!(rr.rdlength().get(), 16);
        assert_eq!(rr.len(), 13 + 10 + 16);
    }
}
