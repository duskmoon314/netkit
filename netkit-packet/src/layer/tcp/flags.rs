//! TCP flags.

use bitflags::bitflags;

use crate::impl_target;

bitflags! {
    /// Tcp flags.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(transparent))]
    pub struct TcpFlags: u8 {
        /// Congestion Window Reduced (CWR).
        const CWR = 0b1000_0000;
        /// ECN-Echo.
        const ECE = 0b0100_0000;
        /// Urgent pointer field is significant.
        const URG = 0b0010_0000;
        /// Acknowledgment field is significant.
        const ACK = 0b0001_0000;
        /// Push Function.
        const PSH = 0b0000_1000;
        /// Reset the connection.
        const RST = 0b0000_0100;
        /// Synchronize sequence numbers.
        const SYN = 0b0000_0010;
        /// No more data from sender.
        const FIN = 0b0000_0001;
    }
}

impl From<u8> for TcpFlags {
    fn from(value: u8) -> Self {
        TcpFlags::from_bits_retain(value)
    }
}

impl From<TcpFlags> for u8 {
    fn from(flags: TcpFlags) -> Self {
        flags.bits()
    }
}

impl_target!(frominto, TcpFlags, u8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        assert_eq!(flags, TcpFlags::SYN | TcpFlags::ACK);
        assert_eq!(flags, TcpFlags::from_bits(0b0001_0010).unwrap());
        assert_eq!(flags.bits(), 0b0001_0010);
        assert_eq!(flags.contains(TcpFlags::SYN), true);
        assert_eq!(flags.contains(TcpFlags::ACK), true);
        assert_eq!(flags.contains(TcpFlags::FIN), false);
        assert_eq!(flags.contains(TcpFlags::RST), false);
        assert_eq!(flags.contains(TcpFlags::URG), false);
        assert_eq!(flags.contains(TcpFlags::ECE), false);
        assert_eq!(flags.contains(TcpFlags::CWR), false);
        assert_eq!(flags.contains(TcpFlags::PSH), false);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_tcp_flags_serde() {
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        let serialized = serde_json::to_string(&flags).unwrap();
        assert_eq!(serialized, r#""ACK | SYN""#);
        let deserialized: TcpFlags = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, flags);
    }

    #[test]
    fn test_tcp_flags_from_u8() {
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        let value: u8 = flags.into();
        assert_eq!(value, 0b0001_0010);
        let flags = TcpFlags::from(value);
        assert_eq!(flags, TcpFlags::SYN | TcpFlags::ACK);
    }
}
