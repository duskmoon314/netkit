//! Dns Name

use std::collections::HashSet;
use std::fmt::Display;

use super::DnsLabel;

/// Error type for DnsName operations
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum DnsNameError {
    /// Compression pointer loop detected
    #[error("Compression pointer loop detected")]
    CompressionLoop,
    /// Invalid compression pointer offset
    #[error("Invalid compression pointer offset: {0}")]
    InvalidOffset(u16),
    /// Label too long
    #[error("Label too long: {0} bytes (max 63)")]
    LabelTooLong(usize),
    /// Name too long
    #[error("Name too long: {0} bytes (max 255)")]
    NameTooLong(usize),
    /// Truncated data
    #[error("Truncated data at offset {0}")]
    Truncated(usize),
}

/// Dns Name
#[derive(Clone, Debug)]
pub struct DnsName<T> {
    data: T,
}

impl<T> DnsName<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new DnsName without validation
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid DNS name
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        DnsName { data }
    }

    /// Get the inner data
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Take the inner data
    #[inline]
    pub fn into_inner(self) -> T {
        self.data
    }

    /// Get the labels as an iterator
    #[inline]
    pub fn labels(&self) -> DnsNameLabelIter<'_, T> {
        DnsNameLabelIter::from(self)
    }

    /// Resolve DNS name with compression pointers to a string
    ///
    /// This method follows compression pointers and returns the fully qualified domain name.
    /// The `dns_packet` parameter should be the full DNS packet (starting from the DNS header).
    ///
    /// # Arguments
    ///
    /// * `dns_packet` - The full DNS packet data for resolving compression pointers
    ///
    /// # Returns
    ///
    /// A string containing the fully qualified domain name with a trailing dot (e.g., "example.com.")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A compression pointer loop is detected
    /// - A compression pointer offset is invalid
    /// - The data is truncated
    pub fn resolve(&self, dns_packet: &[u8]) -> Result<String, DnsNameError> {
        let mut result = String::new();
        let mut visited = HashSet::new();
        let mut offset = 0;
        let data = self.data.as_ref();

        loop {
            if offset >= data.len() {
                break;
            }

            let byte = data[offset];

            // Check for compression pointer (top 2 bits are 11)
            if (byte & 0xC0) == 0xC0 {
                if offset + 1 >= data.len() {
                    return Err(DnsNameError::Truncated(offset));
                }

                // Extract pointer offset (14 bits)
                let ptr_offset =
                    u16::from_be_bytes([data[offset] & 0x3F, data[offset + 1]]) as usize;

                // Check for loops
                if !visited.insert(ptr_offset) {
                    return Err(DnsNameError::CompressionLoop);
                }

                // Check bounds
                if ptr_offset >= dns_packet.len() {
                    return Err(DnsNameError::InvalidOffset(ptr_offset as u16));
                }

                // Recursively resolve from the pointer location
                let remaining = &dns_packet[ptr_offset..];
                let pointed_name = unsafe { DnsName::new_unchecked(remaining) };
                let resolved =
                    pointed_name.resolve_from_offset(dns_packet, ptr_offset, &mut visited)?;
                result.push_str(&resolved);
                break; // Compression pointer ends the name
            }

            // Root label (end of name)
            if byte == 0 {
                // Only add dot if result doesn't already end with one
                if !result.ends_with('.') {
                    result.push('.');
                }
                break;
            }

            // Normal label
            let len = byte as usize;
            if len > 63 {
                return Err(DnsNameError::LabelTooLong(len));
            }

            if offset + 1 + len > data.len() {
                return Err(DnsNameError::Truncated(offset));
            }

            // Extract label text
            let label_bytes = &data[offset + 1..offset + 1 + len];
            let label_str =
                std::str::from_utf8(label_bytes).map_err(|_| DnsNameError::LabelTooLong(len))?;

            result.push_str(label_str);
            result.push('.');

            offset += 1 + len;
        }

        if result.len() > 255 {
            return Err(DnsNameError::NameTooLong(result.len()));
        }

        Ok(result)
    }

    /// Helper method for recursive resolution with loop detection
    fn resolve_from_offset(
        &self,
        dns_packet: &[u8],
        start_offset: usize,
        visited: &mut HashSet<usize>,
    ) -> Result<String, DnsNameError> {
        let mut result = String::new();
        let mut offset = start_offset;

        loop {
            if offset >= dns_packet.len() {
                return Err(DnsNameError::Truncated(offset));
            }

            let byte = dns_packet[offset];

            // Check for compression pointer
            if (byte & 0xC0) == 0xC0 {
                if offset + 1 >= dns_packet.len() {
                    return Err(DnsNameError::Truncated(offset));
                }

                let ptr_offset =
                    u16::from_be_bytes([dns_packet[offset] & 0x3F, dns_packet[offset + 1]])
                        as usize;

                if !visited.insert(ptr_offset) {
                    return Err(DnsNameError::CompressionLoop);
                }

                if ptr_offset >= dns_packet.len() {
                    return Err(DnsNameError::InvalidOffset(ptr_offset as u16));
                }

                // Follow the pointer
                let pointed_name = unsafe { DnsName::new_unchecked(&dns_packet[ptr_offset..]) };
                let resolved = pointed_name.resolve_from_offset(dns_packet, ptr_offset, visited)?;
                result.push_str(&resolved);
                break;
            }

            // Root label
            if byte == 0 {
                // Only add dot if result doesn't already end with one
                if !result.ends_with('.') {
                    result.push('.');
                }
                break;
            }

            // Normal label
            let len = byte as usize;
            if len > 63 {
                return Err(DnsNameError::LabelTooLong(len));
            }

            if offset + 1 + len > dns_packet.len() {
                return Err(DnsNameError::Truncated(offset));
            }

            let label_bytes = &dns_packet[offset + 1..offset + 1 + len];
            let label_str =
                std::str::from_utf8(label_bytes).map_err(|_| DnsNameError::LabelTooLong(len))?;

            result.push_str(label_str);
            result.push('.');

            offset += 1 + len;
        }

        Ok(result)
    }
}

impl From<&str> for DnsName<Vec<u8>> {
    fn from(name: &str) -> Self {
        let mut data = Vec::new();
        for label in name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0);
        DnsName { data }
    }
}

impl<T> Display for DnsName<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for label in self.labels() {
            // write!(f, "{}.", label.as_str().unwrap())?;
            if label.is_normal() {
                if label.len().unwrap().get() > 0 {
                    write!(f, "{}.", label.as_str().unwrap())?;
                }
            } else {
                write!(f, "PTR({})", label.offset().unwrap().get())?;
            }
        }
        Ok(())
    }
}

impl<T> PartialEq<str> for DnsName<T>
where
    T: AsRef<[u8]>,
{
    fn eq(&self, other: &str) -> bool {
        let labels = self.to_string();

        labels == other || labels[..labels.len() - 1] == *other
    }
}

impl<T> PartialEq<&str> for DnsName<T>
where
    T: AsRef<[u8]>,
{
    fn eq(&self, other: &&str) -> bool {
        self.eq(*other)
    }
}

/// Iterator helper for DnsName labels
pub struct DnsNameLabelIter<'a, T> {
    name: &'a DnsName<T>,
    offset: usize,
}

impl<'a, T> From<&'a DnsName<T>> for DnsNameLabelIter<'a, T>
where
    T: AsRef<[u8]>,
{
    fn from(name: &'a DnsName<T>) -> Self {
        DnsNameLabelIter { name, offset: 0 }
    }
}

impl<'a, T> Iterator for DnsNameLabelIter<'a, T>
where
    T: AsRef<[u8]>,
{
    type Item = DnsLabel<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.name.data.as_ref().len() {
            return None;
        }

        let len = self.name.data.as_ref()[self.offset];

        // Check if this is a compression pointer (top 2 bits are 11)
        if (len & 0xC0) == 0xC0 {
            // Compression pointer - need 2 bytes
            if self.offset + 1 >= self.name.data.as_ref().len() {
                return None;
            }
            let label = unsafe {
                DnsLabel::new_unchecked(&self.name.data.as_ref()[self.offset..self.offset + 2])
            };
            self.offset += 2;
            return Some(label);
        }

        let len = len as usize;

        // Check if we have enough bytes for this label
        if self.offset + len + 1 > self.name.data.as_ref().len() {
            return None;
        }

        let label = unsafe {
            DnsLabel::new_unchecked(&self.name.data.as_ref()[self.offset..self.offset + len + 1])
        };
        self.offset += len + 1;
        Some(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_name_labels() {
        let data = b"\x03www\x06google\x03com\x00";
        let name = unsafe { DnsName::new_unchecked(data) };
        let labels: Vec<_> = name.labels().collect();
        assert_eq!(labels.len(), 4);
        assert_eq!(labels[0], "www");
        assert_eq!(labels[1], "google");
        assert_eq!(labels[2], "com");
        assert_eq!(labels[3], "");
    }

    #[test]
    fn dns_name_from_str() {
        let name = DnsName::from("www.google.com");
        assert_eq!(
            name.inner(),
            &vec![
                3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0
            ]
        );

        let labels: Vec<_> = name.labels().collect();
        assert_eq!(labels.len(), 4);
        assert_eq!(labels[0], "www");
        assert_eq!(labels[1], "google");
        assert_eq!(labels[2], "com");
    }

    #[test]
    fn dns_name_eq_str() {
        let data = b"\x03www\x06google\x03com\x00";
        let name = unsafe { DnsName::new_unchecked(data) };

        assert_eq!(name, "www.google.com.");
        assert_eq!(name, "www.google.com");
    }

    #[test]
    fn dns_name_resolve_no_compression() {
        // Simple name without compression: "example.com"
        let name_data = b"\x07example\x03com\x00";
        let name = unsafe { DnsName::new_unchecked(name_data) };

        // DNS packet doesn't matter for non-compressed names
        let dns_packet = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let resolved = name.resolve(dns_packet).unwrap();
        assert_eq!(resolved, "example.com.");
    }

    #[test]
    fn dns_name_resolve_with_compression() {
        // DNS packet structure:
        // Offset 0-11: DNS header (12 bytes)
        // Offset 12: Question name "example.com\0" (13 bytes)
        // Offset 29: Compression pointer to offset 12 (2 bytes: 0xC0 0x0C)
        let mut dns_packet = vec![0u8; 12]; // Header

        // Add question name at offset 12: "example.com\0"
        dns_packet.extend_from_slice(b"\x07example\x03com\x00");

        // The compression pointer: points to offset 12
        let compressed_name = b"\xC0\x0C";
        let name = unsafe { DnsName::new_unchecked(compressed_name) };

        let resolved = name.resolve(&dns_packet).unwrap();
        assert_eq!(resolved, "example.com.");
    }

    #[test]
    fn dns_name_resolve_partial_compression() {
        // DNS packet with:
        // Offset 12: "example.com\0"
        // Name to resolve: "www" + pointer to "example.com"
        let mut dns_packet = vec![0u8; 12]; // Header
        dns_packet.extend_from_slice(b"\x07example\x03com\x00"); // offset 12

        // "www" (3 bytes) + compression pointer to offset 12
        let name_data = b"\x03www\xC0\x0C";
        let name = unsafe { DnsName::new_unchecked(name_data) };

        let resolved = name.resolve(&dns_packet).unwrap();
        assert_eq!(resolved, "www.example.com.");
    }

    #[test]
    fn dns_name_resolve_chained_compression() {
        // DNS packet with:
        // Offset 12: "com\0"
        // Offset 17: "example" + pointer to offset 12
        // Name to resolve: "www" + pointer to offset 17
        let mut dns_packet = vec![0u8; 12]; // Header
        dns_packet.extend_from_slice(b"\x03com\x00"); // offset 12 (5 bytes)
        dns_packet.extend_from_slice(b"\x07example\xC0\x0C"); // offset 17 (10 bytes)

        // "www" + pointer to offset 17
        let name_data = b"\x03www\xC0\x11"; // 0x11 = 17
        let name = unsafe { DnsName::new_unchecked(name_data) };

        let resolved = name.resolve(&dns_packet).unwrap();
        assert_eq!(resolved, "www.example.com.");
    }

    #[test]
    fn dns_name_resolve_compression_loop() {
        // DNS packet with circular pointer:
        // Offset 12: pointer to offset 14
        // Offset 14: pointer to offset 12
        let mut dns_packet = vec![0u8; 12]; // Header
        dns_packet.extend_from_slice(b"\xC0\x0E"); // offset 12: points to 14
        dns_packet.extend_from_slice(b"\xC0\x0C"); // offset 14: points to 12

        let name_data = b"\xC0\x0C"; // Points to offset 12
        let name = unsafe { DnsName::new_unchecked(name_data) };

        let result = name.resolve(&dns_packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(DnsNameError::CompressionLoop)));
    }

    #[test]
    fn dns_name_resolve_invalid_offset() {
        // Compression pointer to offset beyond packet bounds
        let dns_packet = vec![0u8; 12]; // Only header

        let name_data = b"\xC0\xFF"; // Points to offset 255 (out of bounds)
        let name = unsafe { DnsName::new_unchecked(name_data) };

        let result = name.resolve(&dns_packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(DnsNameError::InvalidOffset(_))));
    }
}
