use std::{fmt::Display, str::FromStr};

// use deku::prelude::*;
use serde::Deserialize;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MacAddrError {
    #[error("Invalid MAC address, unexpected number: {0}")]
    ParseInt(#[from] core::num::ParseIntError),

    #[error("Invalid MAC address: Length must be 6 octets")]
    InvalidLength,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct MacAddr {
    octets: [u8; 6],
}

impl MacAddr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self {
            octets: [a, b, c, d, e, f],
        }
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let octets = self.octets.iter().map(|o| format!("{:02x}", o));
        write!(f, "{}", octets.collect::<Vec<_>>().join(":"))
    }
}

impl AsRef<[u8]> for MacAddr {
    fn as_ref(&self) -> &[u8] {
        &self.octets
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self { octets }
    }
}

impl Into<[u8; 6]> for MacAddr {
    fn into(self) -> [u8; 6] {
        self.octets
    }
}

impl TryFrom<&[u8]> for MacAddr {
    type Error = MacAddrError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 6 {
            return Err(MacAddrError::InvalidLength);
        }
        Ok(Self {
            octets: value[..6].try_into().unwrap(),
        })
    }
}

impl Into<u64> for MacAddr {
    fn into(self) -> u64 {
        u64::from_be_bytes([
            0,
            0,
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5],
        ])
    }
}

impl FromStr for MacAddr {
    type Err = MacAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets = s
            .split(':')
            .map(|hex| u8::from_str_radix(hex, 16))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| MacAddrError::InvalidLength)?;
        Ok(Self { octets })
    }
}

impl From<&str> for MacAddr {
    fn from(s: &str) -> Self {
        s.parse().unwrap()
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(MacAddrVisitor)
    }
}

struct MacAddrVisitor;

impl<'de> serde::de::Visitor<'de> for MacAddrVisitor {
    type Value = MacAddr;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter
            .write_str("a MAC address in the form of string (: separated) or array of 6 octets")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.parse().map_err(serde::de::Error::custom)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        match seq.size_hint() {
            Some(6) | None => {}
            Some(size) => return Err(serde::de::Error::invalid_length(size, &"6")),
        }
        let mut octets = [0; 6];
        for i in 0..6 {
            octets[i] = match seq.next_element()? {
                Some(octet) => octet,
                None => return Err(serde::de::Error::invalid_length(i, &"6")),
            }
        }

        Ok(MacAddr::from(octets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addr_parse() {
        assert_eq!(
            "00:11:22:33:44:55".parse::<MacAddr>(),
            Ok(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55))
        );

        assert_eq!(
            "00:11:22:33:44".parse::<MacAddr>(),
            Err(MacAddrError::InvalidLength)
        );
    }

    #[test]
    fn mac_addr_serde() {
        let mac: MacAddr = serde_json::from_str("\"00:11:22:33:44:55\"").unwrap();
        assert_eq!(mac, MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));

        let mac: MacAddr = serde_json::from_str("[0, 17, 34, 51, 68, 85]").unwrap();
        assert_eq!(mac, MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));

        assert!(serde_json::from_str::<MacAddr>("[0, 17, 34, 51, 68]").is_err());
        assert!(serde_json::from_str::<MacAddr>("[0, 17, 34, 51, 68, 85, 102]").is_err());
    }
}
