//! Ethernet MAC address

use core::{convert::TryFrom, fmt::Display, str::FromStr};

use crate::impl_target;

/// Error type for `EthAddr`
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EthAddrError {
    /// Invalid length
    #[error("Invalide EthAddr length: Length must be 6, got {0}")]
    InvalidLength(usize),

    /// Invalid character
    #[error("Invalid EthAddr character: {0}")]
    ParseInt(#[from] core::num::ParseIntError),
}

/// Ethernet MAC address
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct EthAddr {
    octets: [u8; 6],
}

impl EthAddr {
    /// Create a new `EthAddr` from octets
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self {
            octets: [a, b, c, d, e, f],
        }
    }

    /// Create a new `EthAddr` from a slice
    ///
    /// # Panics
    ///
    /// Panics if the slice is not 6 bytes long
    ///
    /// If you want to handle the error, use `try_from` instead
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut octets = [0; 6];
        octets.copy_from_slice(slice);
        Self { octets }
    }
}

impl Display for EthAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

impl AsRef<[u8]> for EthAddr {
    fn as_ref(&self) -> &[u8] {
        &self.octets
    }
}

impl From<[u8; 6]> for EthAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self { octets }
    }
}

impl From<EthAddr> for [u8; 6] {
    fn from(addr: EthAddr) -> Self {
        addr.octets
    }
}

impl TryFrom<&[u8]> for EthAddr {
    type Error = EthAddrError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 6 {
            return Err(EthAddrError::InvalidLength(value.len()));
        }
        Ok(Self::from_slice(value))
    }
}

impl From<EthAddr> for u64 {
    fn from(addr: EthAddr) -> Self {
        u64::from_be_bytes([
            0,
            0,
            addr.octets[0],
            addr.octets[1],
            addr.octets[2],
            addr.octets[3],
            addr.octets[4],
            addr.octets[5],
        ])
    }
}

impl_target!(frominto, EthAddr, [u8; 6]);

impl FromStr for EthAddr {
    type Err = EthAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets = s
            .split(':')
            .map(|hex| u8::from_str_radix(hex, 16))
            .collect::<Result<Vec<_>, _>>()?;
        if octets.len() != 6 {
            return Err(EthAddrError::InvalidLength(octets.len()));
        }
        Ok(Self::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EthAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(EthAddrVisitor)
    }
}

#[cfg(feature = "serde")]
struct EthAddrVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for EthAddrVisitor {
    type Value = EthAddr;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string in the format 'XX:XX:XX:XX:XX:XX' or an array of 6 bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        value.parse().map_err(serde::de::Error::custom)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        match seq.size_hint() {
            Some(6) | None => {
                let mut octets = [0; 6];
                for (i, octet) in octets.iter_mut().enumerate() {
                    *octet = match seq.next_element()? {
                        Some(octet) => octet,
                        None => return Err(serde::de::Error::invalid_length(i, &"6")),
                    }
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(7, &"6"));
                }
                Ok(EthAddr::from(octets))
            }
            Some(size) => Err(serde::de::Error::invalid_length(size, &"6")),
        }
    }
}

/// Create an `EthAddr` from a literal, expression or octets
///
/// # Examples
///
/// ```
/// # use netkit_packet::prelude::*;
/// let addr = eth_addr!("01:23:45:67:89:AB");
/// assert_eq!(addr, EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
///
/// let addr = eth_addr!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB);
/// assert_eq!(addr, EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
/// ```
#[macro_export]
macro_rules! eth_addr {
    ($l: literal) => {
        $l.parse::<$crate::layer::eth::EthAddr>().expect("Invalid EthAddr")
    };

    ($e:expr) => {
        $crate::layer::eth::EthAddr::from($e)
    };

    ($($octet:expr),*) => {
        $crate::layer::eth::EthAddr::new($($octet),*)
    };


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eth_addr_parse() {
        assert_eq!(
            "01:23:45:67:89:AB".parse::<EthAddr>().unwrap(),
            EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB)
        );

        assert_eq!(
            "01:23:45:67:89".parse::<EthAddr>(),
            Err(EthAddrError::InvalidLength(5))
        );

        assert_eq!(
            "01:23:45:67:89:AB:CD".parse::<EthAddr>(),
            Err(EthAddrError::InvalidLength(7))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn eth_addr_serde() {
        let addr: EthAddr = serde_json::from_str("\"01:23:45:67:89:AB\"").unwrap();
        assert_eq!(addr, EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));

        let addr: EthAddr = serde_json::from_str("[1, 35, 69, 103, 137, 171]").unwrap();
        assert_eq!(addr, EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));

        assert!(serde_json::from_str::<EthAddr>("\"01:23:45:67:89\"").is_err());
        assert!(serde_json::from_str::<EthAddr>("\"01:23:45:67:89:AB:CD\"").is_err());
        assert!(serde_json::from_str::<EthAddr>("[1, 35, 69, 103, 137]").is_err());
        assert!(serde_json::from_str::<EthAddr>("[1, 35, 69, 103, 137, 171, 205]").is_err());
    }
}
