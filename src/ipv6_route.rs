use core::{mem, ptr};

/// IPv6 Routing Extension Header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ipv6Route {
    pub nxt_hdr: u8,
    pub hdr_ext_len: u8,
    pub type_: u8,
    pub sgmt_left: u8,
    pub type_data: [u8; 4],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RoutingHeaderType {
    /// Source Route (DEPRECATED) - [RFC2460], [RFC5095]
    SourceRoute,
    /// Nimrod (DEPRECATED)
    Nimrod,
    /// Type 2 Routing Header - [RFC6275]
    Type2,
    /// RPL Source Route Header - [RFC6554]
    RplSourceRoute,
    /// Segment Routing Header (SRH) - [RFC8754]
    SegmentRoutingHeader,
    /// CRH-16 - [RFC9631]
    Crh16,
    /// CRH-32 - [RFC9631]
    Crh32,
    /// RFC3692-style Experiment 1 [2] - [RFC4727]
    Experiment1,
    /// RFC3692-style Experiment 2 [2] - [RFC4727]
    Experiment2,
    /// Reserved
    Reserved,
    /// Represents an unknown or unassigned routing header type
    #[doc(hidden)]
    Unknown(u8),
}

impl RoutingHeaderType {
    /// Converts a `u8` value into a `RoutingHeaderType`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => RoutingHeaderType::SourceRoute,
            1 => RoutingHeaderType::Nimrod,
            2 => RoutingHeaderType::Type2,
            3 => RoutingHeaderType::RplSourceRoute,
            4 => RoutingHeaderType::SegmentRoutingHeader,
            5 => RoutingHeaderType::Crh16,
            6 => RoutingHeaderType::Crh32,
            253 => RoutingHeaderType::Experiment1,
            254 => RoutingHeaderType::Experiment2,
            255 => RoutingHeaderType::Reserved,
            v => RoutingHeaderType::Unknown(v),
        }
    }

    /// Returns the `u8` representation of the `RoutingHeaderType`.
    pub fn as_u8(&self) -> u8 {
        match self {
            RoutingHeaderType::SourceRoute => 0,
            RoutingHeaderType::Nimrod => 1,
            RoutingHeaderType::Type2 => 2,
            RoutingHeaderType::RplSourceRoute => 3,
            RoutingHeaderType::SegmentRoutingHeader => 4,
            RoutingHeaderType::Crh16 => 5,
            RoutingHeaderType::Crh32 => 6,
            RoutingHeaderType::Experiment1 => 253,
            RoutingHeaderType::Experiment2 => 254,
            RoutingHeaderType::Reserved => 255,
            RoutingHeaderType::Unknown(val) => *val,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Ipv6RouteError {
    /// Packet data ended unexpectedly, or a declared length exceeds packet boundaries.
    OutOfBounds,
    /// The Routing header indicates a length that extends beyond the provided packet data.
    UnexpectedEndOfPacket,
    // Like IGMPv3 potentially extend for exceeded stack memory error
}
impl Ipv6Route {
    /// The total size in bytes of default length Routing header
    pub const LEN: usize = mem::size_of::<Ipv6Route>();

    /// Gets the Next Header value.
    pub fn nxt_hdr(&self) -> u8 { self.nxt_hdr }

    /// Sets the Next Header value.
    pub fn set_nxt_hdr(&mut self, nxt_hdr: u8) { self.nxt_hdr = nxt_hdr }

    /// Gets the Header Extension Length value.
    /// This value is the length of the Routing header
    /// in 8-octet units, not including the first 8 octets.
    pub fn hdr_ext_len(&self) -> u8 { self.hdr_ext_len }

    /// Sets the Header Extension Length value.
    pub fn set_hdr_ext_len(&mut self, hdr_ext_len: u8) { self.hdr_ext_len = hdr_ext_len }
    
    /// Gets Rounting Header type casting value to RoutingHeaderType enum
    pub fn type_(&self) -> RoutingHeaderType { RoutingHeaderType::from_u8(self.type_) }
    
    /// Sets the Routing Header type converting value from RoutingHeaderType enum
    pub fn set_type(&mut self, type_: RoutingHeaderType) { self.type_ = type_.as_u8() }
    
    /// Gets the Segments Left value
    pub fn sgmt_left(&self) -> u8 { self.sgmt_left }
    
    /// Sets the Segments Left value
    pub fn set_sgmt_left(&mut self, sgmt_left: u8) { self.sgmt_left = sgmt_left }
    
    /// Gets a slice to the first 4 bytes of Type-specific data
    pub fn type_data(&self) -> &[u8; 4] { &self.type_data }
    
    /// Sets Type-specific data via provided 4-byte slice
    pub fn set_type_data(&mut self, type_data: [u8; 4]) {
        self.type_data = type_data;
    }

    /// Calculates the total length of the Routing header in bytes.
    /// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
    /// So, total length = (hdr_ext_len + 1) * 8.
    pub fn total_hdr_len(&self) -> usize { (self.hdr_ext_len as usize + 1) * 8 }
    
    /// Calculates the total length of the Type-specific data field in bytes.
    /// Total Header Length - 4 bytes (for nxt_hdr, hdr_ext_len, type_, and sgmt_left)
    pub fn total_type_data_len(&self) -> usize { self.total_hdr_len().saturating_sub(4) }
    
    
    pub unsafe fn parse_additional_type_data_to_u8_slice(
        header_ptr: *const Ipv6Route,
        packet_end_ptr: *const u8,
        output_type_data_slice: &mut [u8],
    ) -> Result<usize, Ipv6RouteError> {
        //TODO mirror implementation from HopOpt for bounds checking and parsing
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u8_known_types() {
        assert_eq!(RoutingHeaderType::from_u8(0), RoutingHeaderType::SourceRoute);
        assert_eq!(RoutingHeaderType::from_u8(4), RoutingHeaderType::SegmentRoutingHeader);
        assert_eq!(RoutingHeaderType::from_u8(253), RoutingHeaderType::Experiment1);
        assert_eq!(RoutingHeaderType::from_u8(255), RoutingHeaderType::Reserved);
    }

    #[test]
    fn test_from_u8_unknown_types() {
        // Test values within the unassigned range (7-252)
        assert_eq!(RoutingHeaderType::from_u8(7), RoutingHeaderType::Unknown(7));
        assert_eq!(RoutingHeaderType::from_u8(100), RoutingHeaderType::Unknown(100));
        assert_eq!(RoutingHeaderType::from_u8(252), RoutingHeaderType::Unknown(252));

        // Test a value outside the typical defined range, though technically covered by 7..=252
        // for `u8` it's good to ensure the catch-all works.
        // For example, if we were to define 256 for some reason (not a u8 though).
        // Here, it correctly maps to Unknown for any non-explicitly matched value.
        assert_eq!(RoutingHeaderType::from_u8(8), RoutingHeaderType::Unknown(8));
    }

    #[test]
    fn test_as_u8_known_types() {
        assert_eq!(RoutingHeaderType::SourceRoute.as_u8(), 0);
        assert_eq!(RoutingHeaderType::Crh32.as_u8(), 6);
        assert_eq!(RoutingHeaderType::Reserved.as_u8(), 255);
    }

    #[test]
    fn test_as_u8_unknown_type() {
        assert_eq!(RoutingHeaderType::Unknown(123).as_u8(), 123);
        assert_eq!(RoutingHeaderType::Unknown(7).as_u8(), 7);
    }
}