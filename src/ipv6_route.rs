use crate::chunk_reader;
use core::{mem};

/// IPv6 Routing Extension Header
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ipv6Route {
    pub next_hdr: u8,
    pub hdr_ext_len: u8,
    pub type_: u8,
    pub sgmt_left: u8,
    pub type_data: [u8; 4],
}

const TYPE_SPECIFIC_CHUNK_LEN: usize = mem::size_of::<u64>();

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
    pub fn next_hdr(&self) -> u8 { self.next_hdr }

    /// Sets the Next Header value.
    pub fn set_next_hdr(&mut self, next_hdr: u8) { self.next_hdr = next_hdr }

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
    pub fn total_hdr_len(&self) -> usize { (self.hdr_ext_len as usize + 1) << 3 }

    /// Calculates the total length of the Type-specific data field in bytes.
    /// Total Header Length - 4 bytes (for next_hdr, hdr_ext_len, type_, and sgmt_left)
    pub fn total_type_data_len(&self) -> usize { self.total_hdr_len().saturating_sub(4) }


    /// Extracts the variable-length type-specific data from the IPv6 Routing header
    /// into a caller-provided slice of `u64`.
    ///
    /// The IPv6 Routing header's `hdr_ext_len` field determines the total length of
    /// the header, from which the length of the type-specific data is derived. The
    /// type-specific data is the data that follows the fixed part of the IPv6 Routing
    /// header. This function reads the type-specific data in 8-byte (u64) chunks.
    ///
    /// # Safety
    /// This method is unsafe because it performs raw pointer arithmetic and memory access.
    /// The caller must ensure:
    /// - The Ipv6Route instance points to valid memory containing a complete IPv6 Routing header
    /// - The memory region from the Ipv6Route through the end of the type-specific data is valid and accessible
    /// - The total length calculated from hdr_ext_len does not exceed available memory bounds
    ///
    /// # Arguments
    /// - `output_data_slice`: A mutable slice of `u64` where the parsed type-specific data will be
    ///   written. Data is read from the packet (assumed to be in network byte order)
    ///   and converted to `u64` values in host byte order.
    ///
    /// # Returns
    /// A Result containing:
    /// - Ok(usize): The number of complete u64 words successfully read from the type-specific data and written
    ///   to `output_data_slice`. This may be:
    ///   - 0 if no type-specific data is present beyond the fixed header
    ///   - Less than the total available type-specific data if:
    ///     - `output_data_slice` is too small to hold all data words
    ///     - The remaining type-specific data bytes are not enough for a complete u64 word
    /// - Err(ChunkReaderError): If an error occurred during reading, such as:
    ///   - UnexpectedEndOfPacket: If the packet data ends unexpectedly
    ///   - InvalidChunkLength: If the chunk length is not equal to the size of u64
    pub unsafe fn parse_additional_type_data(&self, output_data_slice: &mut [u64]) -> Result<usize, chunk_reader::ChunkReaderError> {
        let self_ptr: *const Ipv6Route = self;
        let self_ptr_u8: *const u8 = self_ptr as *const u8;
        let total_hdr_len = self.total_hdr_len();
        let start_data_ptr = (self_ptr_u8).add(Ipv6Route::LEN);
        let end_data_ptr = (self_ptr_u8).add(total_hdr_len);

        if total_hdr_len <= Ipv6Route::LEN {
            return Ok(0);
        }

        chunk_reader::read_chunks(start_data_ptr, end_data_ptr, output_data_slice, TYPE_SPECIFIC_CHUNK_LEN)
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

    // --- Tests for Ipv6Route Struct ---
    #[test]
    fn test_ipv6route_len_constant() {
        assert_eq!(Ipv6Route::LEN, 8); // next_hdr, hdr_ext_len, type_, sgmt_left (4 bytes) + type_data (4 bytes)
        assert_eq!(Ipv6Route::LEN, mem::size_of::<Ipv6Route>());
    }

    #[test]
    fn test_getters_setters() {
        let mut header = Ipv6Route {
            next_hdr: 0,
            hdr_ext_len: 0,
            type_: 0,
            sgmt_left: 0,
            type_data: [0; 4],
        };

        // Test next_hdr
        header.set_next_hdr(17); // UDP
        assert_eq!(header.next_hdr(), 17);

        // Test hdr_ext_len
        header.set_hdr_ext_len(2); // 2 * 8 = 16 additional bytes
        assert_eq!(header.hdr_ext_len(), 2);

        // Test type_ and type_data
        header.set_type(RoutingHeaderType::SegmentRoutingHeader);
        assert_eq!(header.type_(), RoutingHeaderType::SegmentRoutingHeader);
        assert_eq!(header.type_().as_u8(), 4);

        let data_slice: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        header.set_type_data(data_slice);
        assert_eq!(header.type_data(), &data_slice);

        // Test sgmt_left
        header.set_sgmt_left(5);
        assert_eq!(header.sgmt_left(), 5);
    }

    #[test]
    fn test_total_hdr_len() {
        let mut header = Ipv6Route {
            next_hdr: 0,
            hdr_ext_len: 0, // (0 + 1) * 8 = 8 bytes
            type_: 0,
            sgmt_left: 0,
            type_data: [0; 4],
        };
        assert_eq!(header.total_hdr_len(), 8);

        header.set_hdr_ext_len(1); // (1 + 1) * 8 = 16 bytes
        assert_eq!(header.total_hdr_len(), 16);

        header.set_hdr_ext_len(5); // (5 + 1) * 8 = 48 bytes
        assert_eq!(header.total_hdr_len(), 48);

        // Max hdr_ext_len = 255 -> (255 + 1) * 8 = 2048 bytes
        header.set_hdr_ext_len(255);
        assert_eq!(header.total_hdr_len(), 2048);
    }

    #[test]
    fn test_total_type_data_len() {
        let mut header = Ipv6Route {
            next_hdr: 0,
            hdr_ext_len: 0, // Total header len = 8 bytes
            type_: 0,
            sgmt_left: 0,
            type_data: [0; 4],
        };
        // 8 (total) - 4 (fixed) = 4 bytes of type-specific data (just type_data field)
        assert_eq!(header.total_type_data_len(), 4);

        header.set_hdr_ext_len(1); // Total header len = 16 bytes
        // 16 (total) - 4 (fixed) = 12 bytes of type-specific data
        assert_eq!(header.total_type_data_len(), 12);

        header.set_hdr_ext_len(255); // Total header len = 2048 bytes
        // 2048 (total) - 4 (fixed) = 2044 bytes of type-specific data
        assert_eq!(header.total_type_data_len(), 2044);
    }


    // --- Tests for parse_additional_type_data ---

    #[test]
    fn test_parse_additional_type_data_basic() {
        // Create a header with hdr_ext_len = 2 => total_hdr_len = (2+1)*8 = 24 bytes
        // 24 - 8 (Ipv6Route::LEN) = 16 additional bytes (2 u64s).
        let mut packet_data = [0u8; 24];
        packet_data[1] = 2; // hdr_ext_len = 2
        // First 8 bytes of additional data (first u64)
        packet_data[8..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        // Second 8 bytes of additional data (second u64)
        packet_data[16..24].copy_from_slice(&[0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);

        // Get a reference to the header
        let header = unsafe { &*(packet_data.as_ptr() as *const Ipv6Route) };
        let mut output_slice = [0u64; 2]; // Expecting two u64s

        // Call the function
        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };

        // Verify the results
        assert_eq!(result, Ok(2));
        assert_eq!(output_slice[0], u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
        assert_eq!(output_slice[1], u64::from_be_bytes([0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]));
    }

    #[test]
    fn test_parse_additional_type_data_empty_output_slice() {
        // Create a header with hdr_ext_len = 1 => total_hdr_len = (1+1)*8 = 16 bytes
        // 16 - 8 (Ipv6Route::LEN) = 8 additional bytes (1 u64).
        let mut packet_data = [0u8; 16];
        packet_data[1] = 1; // hdr_ext_len = 1
        packet_data[8..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        // Get a reference to the header
        let header = unsafe { &*(packet_data.as_ptr() as *const Ipv6Route) };
        let mut output_slice = [0u64; 0]; // Empty output slice

        // Call the function
        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };

        // Verify the results - should return 0 because the output slice is empty
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_parse_additional_type_data_output_slice_too_small() {
        // Create a header with hdr_ext_len = 2 => total_hdr_len = (2+1)*8 = 24 bytes
        // 24 - 8 (Ipv6Route::LEN) = 16 additional bytes (2 u64s).
        let mut packet_data = [0u8; 24];
        packet_data[1] = 2; // hdr_ext_len = 2
        packet_data[8..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        packet_data[16..24].copy_from_slice(&[0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);

        // Get a reference to the header
        let header = unsafe { &*(packet_data.as_ptr() as *const Ipv6Route) };
        let mut output_slice = [0u64; 1]; // Output slice too small (only 1 u64)

        // Call the function
        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };

        // Verify the results - should return 1 because the output slice can only hold 1 u64
        assert_eq!(result, Ok(1));
        assert_eq!(output_slice[0], u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
    }

    #[test]
    fn test_parse_additional_type_data_zero_additional_data() {
        // Create a header with hdr_ext_len = 0 => total_hdr_len = (0+1)*8 = 8 bytes
        // 8 - 8 (Ipv6Route::LEN) = 0 additional bytes.
        let mut packet_data = [0u8; 8];
        packet_data[1] = 0; // hdr_ext_len = 0

        // Get a reference to the header
        let header = unsafe { &*(packet_data.as_ptr() as *const Ipv6Route) };
        let mut output_slice = [0u64; 1]; // Output slice with room for 1 u64

        // Call the function
        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };

        // Verify the results - should return 0 because there's no additional data
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_parse_additional_type_data_partial_data() {
        // Create a header with hdr_ext_len = 0 => total_hdr_len = (0+1)*8 = 8 bytes
        // We'll add 4 bytes of additional data, which is not enough for a complete u64 (8 bytes)
        let mut packet_data = [0u8; 12];
        packet_data[1] = 0; // hdr_ext_len = 0 (total header length = 8 bytes)
        packet_data[8..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]); // 4 bytes of additional data

        // Get a reference to the header
        let header = unsafe { &*(packet_data.as_ptr() as *const Ipv6Route) };
        let mut output_slice = [0u64; 1]; // Output slice with room for 1 u64

        // Call the function
        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };

        // Verify the results - should return 0 because there's no additional data
        // (the function only considers data after the standard header length)
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_parse_additional_type_data_max_header_length() {
        // Test with maximum hdr_ext_len = 255
        // total_hdr_len = (255 + 1) * 8 = 2048 bytes
        // We'll create a smaller packet with just a few u64s to test the principle
        const TOTAL_LEN: usize = 40; // 8 (header) + 32 (4 u64s)
        let mut packet_data = [0u8; TOTAL_LEN];
        packet_data[1] = 4; // hdr_ext_len = 4 (enough for 4 u64s)

        // Fill the additional data with recognizable patterns
        for i in 0..4 {
            let start = 8 + i * 8;
            let end = start + 8;
            let value = (i as u8 + 1) * 0x11;
            packet_data[start..end].fill(value);
        }

        // Get a reference to the header
        let header = unsafe { &*(packet_data.as_ptr() as *const Ipv6Route) };
        let mut output_slice = [0u64; 4]; // Output slice with room for 4 u64s

        // Call the function
        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };

        // Verify the results
        assert_eq!(result, Ok(4));
        for i in 0..4 {
            let value = (i as u8 + 1) * 0x11;
            let expected = u64::from_be_bytes([value, value, value, value, value, value, value, value]);
            assert_eq!(output_slice[i], expected);
        }
    }

    #[test]
    fn test_parse_additional_type_data_misaligned() {
        // Create a buffer with an offset to simulate misaligned data
        let mut buffer = [0u8; 32];

        // Place the header at offset 1 to make it misaligned
        buffer[1] = 0; // next_hdr
        buffer[2] = 2; // hdr_ext_len = 2 (total_hdr_len = 24 bytes)
        buffer[3] = 0; // type_
        buffer[4] = 0; // sgmt_left
        // type_data (4 bytes) at buffer[5..9]
        buffer[5..9].fill(0xAA);

        // Additional data (16 bytes = 2 u64s) at buffer[9..25]
        buffer[9..17].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        buffer[17..25].copy_from_slice(&[0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);

        // Get a reference to the header (at offset 1)
        let header = unsafe { &*(buffer[1..].as_ptr() as *const Ipv6Route) };
        let mut output_slice = [0u64; 2]; // Output slice with room for 2 u64s

        // Call the function
        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };

        // Verify the results
        assert_eq!(result, Ok(2));
        assert_eq!(output_slice[0], u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
        assert_eq!(output_slice[1], u64::from_be_bytes([0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]));
    }

    #[test]
    fn test_parse_additional_type_data_corrupt_header_len() {
        const PACKET_SIZE: usize = 12; // IPv6 Route should be 16 bytes but we only provide 12
        let packet_data: [u8; PACKET_SIZE] = [
            59, 0, // next_hdr, hdr_ext_len = 1 (total IPv6 Route 16 bytes)
            0, 0, // type_, sgmt_left
            0, 0, 0, 0, // type_data
            // Only 4 bytes of the expected 8 bytes of additional type-specific data
            0x11, 0x22, 0x33, 0x44,
        ];

        let header = unsafe { &*(packet_data.as_ptr() as *const Ipv6Route) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };
        assert_eq!(result, Ok(0));
    }
}
