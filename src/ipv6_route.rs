use crate::chunk_reader;
use core::{mem, ptr};

const TYPE_SPECIFIC_CHUNK_LEN: usize = mem::size_of::<u64>();

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

    /// Reads additional type-specific data from an IPv6 Routing header into a caller-provided slice.
    ///
    /// The function reads data in 8-byte (u64) chunks from the packet data region
    /// immediately following the standard `Ipv6Route` header. The total amount of
    /// additional data to be processed is determined by the `hdr_ext_len` field of
    /// the `Ipv6Route` header, which specifies the length of the Routing header
    /// in 8-octet units, not including the first 8 octets.
    ///
    /// # Safety
    /// - `header_ptr` must be a valid pointer to the start of an `Ipv6Route`
    ///   structure within the packet data. This function will validate its
    ///   accessibility based on `packet_end_ptr` and `hdr_ext_len`.
    /// - `packet_end_ptr` must point to the byte *after* the last valid byte
    ///   of the packet data.
    /// - The memory region from `header_ptr` up to the total length indicated by
    ///   `hdr_ext_len` (i.e., `(hdr_ext_len + 1) * 8` bytes) must be valid,
    ///   accessible, and part of the packet data.
    ///
    /// # Arguments
    /// - `header_ptr`: Pointer to where the `Ipv6Route` header is expected to
    ///   start in the packet.
    /// - `packet_end_ptr`: Pointer indicating the end of valid packet data.
    /// - `output_data_slice`: A mutable slice of `u64` (e.g., from a
    ///   stack-allocated array) where the additional type-specific data will be
    ///   written. Data is read from the packet in network byte order (big-endian)
    ///   and converted to `u64` in host byte order.
    ///
    /// # Returns
    /// - `Ok(count)`: The number of `u64` elements successfully read from the
    ///   additional data section and written into `output_data_slice`. This count
    ///   may be less than the total available if `output_data_slice` is too small
    ///   or if the remaining data is not a multiple of 8 bytes.
    /// - `Err(Ipv6RouteError)`: If an error occurs, such as:
    ///     - `Ipv6RouteError::OutOfBounds`: If reading the base `Ipv6Route` header
    ///       would go beyond `packet_end_ptr`.
    ///     - `Ipv6RouteError::UnexpectedEndOfPacket`: If the total length defined by
    ///       `hdr_ext_len` extends beyond `packet_end_ptr`.
    pub unsafe fn parse_additional_type_data_to_u8_slice(
        header_ptr: *const Ipv6Route,
        packet_end_ptr: *const u8,
        output_data_slice: &mut [u64],
    ) -> Result<usize, Ipv6RouteError> {
        // Ensure we can read through the standard struct length
        if (header_ptr as *const u8).add(mem::size_of::<Ipv6Route>()) > packet_end_ptr { 
            return Err(Ipv6RouteError::OutOfBounds);
        }

        // Read hdr_ext_len
        let num_data_ptr = ptr::addr_of!((*header_ptr).hdr_ext_len);
        let num_data_be = unsafe {ptr::read_unaligned(num_data_ptr)};
        let hdr_ext_len_val = u8::from_be(num_data_be);

        if hdr_ext_len_val == 0 {
            return Ok(0);
        }

        // Calculate the total Routing header length and verify against packet boundaries.
        // Add 1 to cover the first octet of the Routing header
        let total_hdr_len = (hdr_ext_len_val as usize + 1) << 3;
        if (header_ptr as *const u8).add(total_hdr_len) > packet_end_ptr {
            return Err(Ipv6RouteError::UnexpectedEndOfPacket);
        }

        // Determine start and end pointers for "additional" type-specific data
        let mut current_data_ptr = (header_ptr as *const u8).add(mem::size_of::<Ipv6Route>());
        let additional_data_end_ptr = (header_ptr as *const u8).add(total_hdr_len);
        let mut data_packed_count: usize = 0;

        while current_data_ptr < additional_data_end_ptr {

            if data_packed_count >= output_data_slice.len() {
                // Consider adding Ipv6RouteError for dst slice full
                break;
            }

            // Check if there are enough bytes remaining in THIS Rounting header's additional data
            // to read a full u64 (8 bytes). We must not read beyond additional_data_end_ptr
            if current_data_ptr.add(mem::size_of::<u64>()) > additional_data_end_ptr {
                // Consider adding Ipv6RouteError to signal leftover bytes
                break;
            }

            let mut packed_data_bytes = [0u8; 8];

            // Read 8 bytes from current_data_ptr into packed_option_bytes.
            ptr::copy_nonoverlapping(
                current_data_ptr,           // Source pointer from packet data
                packed_data_bytes.as_mut_ptr(), // Destination buffer
                mem::size_of::<u64>(),      // Length to copy (8 bytes)
            );

            current_data_ptr = current_data_ptr.add(mem::size_of::<u64>());

            // Convert the 8 bytes into a u64
            output_data_slice[data_packed_count] = u64::from_be_bytes(packed_data_bytes);
            data_packed_count += 1;
        }

        Ok(data_packed_count)
    }

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
    /// The number of complete u64 words successfully read from the type-specific data and written
    /// to `output_data_slice`. This may be:
    /// - 0 if no type-specific data is present beyond the fixed header
    /// - Less than the total available type-specific data if:
    ///   - `output_data_slice` is too small to hold all data words
    ///   - The remaining type-specific data bytes are not enough for a complete u64 word
    pub unsafe fn parse_additional_type_data(&self, output_data_slice: &mut [u64]) -> usize {
        let self_ptr: *const Ipv6Route = self;
        let self_ptr_u8: *const u8 = self_ptr as *const u8;
        let total_hdr_len = self.total_hdr_len();
        let start_data_ptr = (self_ptr_u8).add(Ipv6Route::LEN);
        let end_data_ptr = (self_ptr_u8).add(total_hdr_len);

        if total_hdr_len <= Ipv6Route::LEN {
            return 0;
        }

        chunk_reader::read_u64_chunks(start_data_ptr, end_data_ptr, output_data_slice, TYPE_SPECIFIC_CHUNK_LEN)
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

    // --- Tests for parse_additional_type_data_to_u8_slice ---

    #[test]
    fn test_parse_additional_data_hdr_ext_len_zero() {
        // A minimal Routing Header with hdr_ext_len = 0
        // This means the total header length is 8 bytes (Ipv6Route::LEN),
        // and there's no "additional" data beyond the `type_data` field.
        let mut header_bytes = [0u8; Ipv6Route::LEN];
        header_bytes[1] = 0; // hdr_ext_len = 0

        let header_ptr = header_bytes.as_ptr() as *const Ipv6Route;
        let packet_end_ptr = unsafe { header_bytes.as_ptr().add(header_bytes.len()) };
        let mut output_slice = [0u64; 10]; // Large enough output slice

        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        assert_eq!(result, Ok(0), "No additional data expected when hdr_ext_len is 0");
    }

    #[test]
    fn test_parse_additional_data_single_u64() {
        // hdr_ext_len = 1 => total_hdr_len = (1+1)*8 = 16 bytes
        // Fixed part = 4 bytes, initial type_data = 4 bytes.
        // So, 16 - 8 (Ipv6Route::LEN) = 8 additional bytes (1 u64).
        let mut packet_data = [0u8; 16];
        packet_data[1] = 1; // hdr_ext_len = 1
        // The first 4 bytes of type-specific data are `type_data` in the struct.
        // The next 8 bytes are what `parse_additional_type_data_to_u8_slice` should read.
        packet_data[8..16].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let header_ptr = packet_data.as_ptr() as *const Ipv6Route;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1]; // Expecting one u64

        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        assert_eq!(result, Ok(1));
        assert_eq!(output_slice[0], u64::from_be_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]));
    }

    #[test]
    fn test_parse_additional_data_multiple_u64s() {
        // hdr_ext_len = 2 => total_hdr_len = (2+1)*8 = 24 bytes
        // 24 - 8 (Ipv6Route::LEN) = 16 additional bytes (2 u64s).
        let mut packet_data = [0u8; 24];
        packet_data[1] = 2; // hdr_ext_len = 2
        // First 8 bytes of additional data (first u64)
        packet_data[8..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        // Second 8 bytes of additional data (second u64)
        packet_data[16..24].copy_from_slice(&[0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);

        let header_ptr = packet_data.as_ptr() as *const Ipv6Route;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 2]; // Expecting two u64s

        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        assert_eq!(result, Ok(2));
        assert_eq!(output_slice[0], u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
        assert_eq!(output_slice[1], u64::from_be_bytes([0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]));
    }

    #[test]
    fn test_parse_additional_data_output_slice_too_small() {
        // hdr_ext_len = 2 => total_hdr_len = 24 bytes (expecting 2 u64s of additional data)
        let mut packet_data = [0u8; 24];
        packet_data[1] = 2; // hdr_ext_len = 2
        packet_data[8..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        packet_data[16..24].copy_from_slice(&[0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);


        let header_ptr = packet_data.as_ptr() as *const Ipv6Route;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1]; // Output slice too small for all additional data (only 1 u64)

        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        // It should read the first u64 and stop because the output slice is full.
        assert_eq!(result, Ok(1));
        assert_eq!(output_slice[0], u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
    }

    #[test]
    fn test_parse_additional_data_out_of_bounds_initial_header() {
        // Packet data is smaller than the fixed Ipv6Route header struct (8 bytes)
        let packet_data = [0u8; 4]; // Only 4 bytes, cannot even read `type_data` safely.

        let header_ptr = packet_data.as_ptr() as *const Ipv6Route;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        assert_eq!(result, Err(Ipv6RouteError::OutOfBounds));
    }

    #[test]
    fn test_parse_additional_data_unexpected_end_of_packet() {
        // hdr_ext_len = 1 => total_hdr_len = 16 bytes.
        // But packet_data only has 10 bytes in total (8 fixed + 2 additional).
        // This is less than the required 16 bytes.
        let mut packet_data = [0u8; 10];
        packet_data[1] = 1; // hdr_ext_len = 1 (implies 8 additional bytes needed after Ipv6Route::LEN)

        let header_ptr = packet_data.as_ptr() as *const Ipv6Route;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        assert_eq!(result, Err(Ipv6RouteError::UnexpectedEndOfPacket));
    }

    #[test]
    fn test_parse_additional_data_packet_just_fits() {
        // hdr_ext_len = 1 => total_hdr_len = 16 bytes
        // Packet data is exactly 16 bytes
        let mut packet_data = [0u8; 16];
        packet_data[1] = 1; // hdr_ext_len = 1
        packet_data[8..16].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);

        let header_ptr = packet_data.as_ptr() as *const Ipv6Route;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        assert_eq!(result, Ok(1));
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]));
    }

    #[test]
    fn test_parse_additional_data_hdr_ext_len_max() {
        // Test with maximum hdr_ext_len = 255
        // total_hdr_len = (255 + 1) * 8 = 2048 bytes
        const TOTAL_LEN: usize = 2048;
        let mut packet_data = [0u8; TOTAL_LEN];
        packet_data[1] = 255; // hdr_ext_len = 255

        // Fill some data for validation (e.g., last u64)
        let last_u64_start_idx = TOTAL_LEN - 8;
        packet_data[last_u64_start_idx..].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        let header_ptr = packet_data.as_ptr() as *const Ipv6Route;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };

        // Calculate expected number of additional u64s
        let expected_additional_bytes = TOTAL_LEN - Ipv6Route::LEN; // 2048 - 8 = 2040
        let expected_u64_count = expected_additional_bytes / mem::size_of::<u64>(); // 2040 / 8 = 255

        let mut output_slice = [0u64; 255]; // Fixed-size array for max expected u64s

        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        assert_eq!(result, Ok(expected_u64_count));
        assert_eq!(output_slice[expected_u64_count - 1], u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
    }


    #[test]
    fn test_parse_additional_data_misaligned_header_ptr() {
        // Simulate header starting 1 byte into raw_packet_data, making it unaligned.
        // We'll create a buffer larger than needed to allow for the offset.
        // The total data needed for hdr_ext_len = 1 is 16 bytes.
        // So, a buffer of 1 (offset) + 16 (header) = 17 bytes minimum.
        const BUFFER_LEN: usize = 17;
        let mut raw_packet_data = [0u8; BUFFER_LEN];

        // The effective header starts at raw_packet_data[1]
        // This is where next_hdr would be, then hdr_ext_len at raw_packet_data[2].
        // So, `hdr_ext_len` is at `raw_packet_data[1 + 1]`.
        // The value `1` for hdr_ext_len means total length 16 bytes.
        // `Ipv6Route::LEN` is 8 bytes.
        // The `Ipv6Route` struct itself (8 bytes) would span `raw_packet_data[1..9]`.
        // The additional data would start at `raw_packet_data[1 + Ipv6Route::LEN]` which is `raw_packet_data[9]`.
        // It needs to read 8 bytes from `raw_packet_data[9..17]`.
        raw_packet_data[2] = 1; // Set hdr_ext_len = 1

        // Fill additional data starting from `raw_packet_data[9]`
        raw_packet_data[9..17].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        let header_ptr = unsafe { raw_packet_data.as_ptr().add(1) as *const Ipv6Route }; // Unaligned pointer
        let packet_end_ptr = unsafe { raw_packet_data.as_ptr().add(raw_packet_data.len()) };
        let mut output_slice = [0u64; 1];

        // The current implementation uses `ptr::copy_nonoverlapping` which is safe for unaligned pointers
        // as long as the memory region itself is valid and bounds are checked.
        let result = unsafe {
            Ipv6Route::parse_additional_type_data_to_u8_slice(
                header_ptr,
                packet_end_ptr,
                &mut output_slice,
            )
        };
        assert_eq!(result, Ok(1));
        assert_eq!(output_slice[0], u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
    }

    // --- Tests for parse_additional_type_data ---

    #[test]
    fn test_parse_additional_type_data() {
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

        // Call the new function
        let result = unsafe { header.parse_additional_type_data(&mut output_slice) };

        // Verify the results
        assert_eq!(result, 2);
        assert_eq!(output_slice[0], u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
        assert_eq!(output_slice[1], u64::from_be_bytes([0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]));
    }
}
