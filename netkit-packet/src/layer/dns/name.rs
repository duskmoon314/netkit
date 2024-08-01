//! Dns Name

use std::fmt::Display;

use super::DnsLabel;

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
    pub fn labels(&self) -> DnsNameLabelIter<T> {
        DnsNameLabelIter::from(self)
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

        let len = self.name.data.as_ref()[self.offset] as usize;
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
}
