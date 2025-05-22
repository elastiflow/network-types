use core::{mem, ptr};

/// IPv6 Hop-by-Hop Options Extension Header
/// 
/// This struct can also be used to represent IPv6 Destination Options Extension Header
/// as both headers share the same format. The only difference is in the Next Header value
/// and their position in the IPv6 extension header chain.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct HopOpt{
    pub nxt_hdr: u8,
    pub hdr_ext_len: u8,
    /// The first 6 bytes of the options field.
    /// If hdr_ext_len is 0, these are all the options.
    /// If hdr_ext_len > 0, additional options follow these 6 bytes.
    pub opt_data: [u8; 6], // These 6 octets options are always present
}

/// Errors that can occur during Hop-by-Hop option parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum HopOptError {
    /// Packet data ended unexpectedly, or a declared length exceeds packet boundaries.
    OutOfBounds,
    /// The Hop-by-Hop header indicates a length that extends beyond the provided packet data.
    UnexpectedEndOfPacket,
}

impl HopOpt{
    /// The total size in bytes of default length HbH header
    pub const LEN: usize = mem::size_of::<HopOpt>();

    /// Gets the Next Header value.
    pub fn nxt_hdr(&self) -> u8 {
        self.nxt_hdr
    }

    /// Sets the Next Header value.
    pub fn set_nxt_hdr(&mut self, nxt_hdr: u8) {
        self.nxt_hdr = nxt_hdr;
    }

    /// Gets the Header Extension Length value.
    /// This value is the length of the Hop-by-Hop Options header
    /// in 8-octet units, not including the first 8 octets.
    pub fn hdr_ext_len(&self) -> u8 {
        self.hdr_ext_len
    }

    /// Sets the Header Extension Length value.
    pub fn set_hdr_ext_len(&mut self, hdr_ext_len: u8) {
        self.hdr_ext_len = hdr_ext_len;
    }

    /// Gets a slice to the first 6 bytes of options data
    pub fn opt_data(&self) -> &[u8; 6] {
        &self.opt_data
    }

    /// Calculates the total length of the Hop-by-Hop header in bytes.
    /// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
    /// So, total length = (hdr_ext_len + 1) * 8.
    pub fn total_hdr_len(&self) -> usize {
        (self.hdr_ext_len as usize + 1) << 3
    }

    /// Calculates the total length of the options field in bytes.
    /// Options field = Total Header Length - 2 bytes (for nxt_hdr and hdr_ext_len).
    pub fn total_opts_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(2)
    }

    /// Parses Hop-by-Hop options from the variable-length options field of a Hop-by-Hop
    /// Options header into a caller-provided slice of u64.
    ///
    /// This function reads the options data that follows the initial 'Next Header' and
    /// 'Hdr Ext Len' fields of the Hop-by-Hop Options header. The length of the
    /// options data is determined by the 'Hdr Ext Len' field. Options are read in
    /// 8-byte (u64) chunks. This function is intended for scenarios where options
    /// or their data are aligned and can be meaningfully interpreted as u64 values.
    ///
    /// # Safety
    /// - `header_ptr` must be a valid pointer to the start of a Hop-by-Hop Options
    ///   header structure (e.g., `HopOptHdr`) within the packet data. The function
    ///   relies on this pointer to access the 'Hdr Ext Len' field and to determine
    ///   the start of the options data.
    /// - `packet_end_ptr` must point to the byte *after* the last valid byte
    ///   of the packet data.
    /// - The memory region covered by the Hop-by-Hop Options header, as determined by its
    ///   'Hdr Ext Len' field (i.e., `(hdr_ext_len_value + 1) * 8` bytes from `header_ptr`),
    ///   must be valid, accessible, and part of the packet data.
    ///
    /// # Arguments
    /// - `header_ptr`: Pointer to the beginning of the Hop-by-Hop Options header
    ///   in the packet.
    /// - `packet_end_ptr`: Pointer indicating the end of valid packet data.
    /// - `output_options_slice`: A mutable slice of `u64` where the parsed options data
    ///   will be written. Data is read from the packet (assumed to be in network
    ///   byte order) and converted to `u64` values (host byte order).
    ///
    /// # Returns
    /// - `Ok(count)`: The number of `u64` elements successfully read from the options
    ///   field and written into `output_options_slice`. This count may be less than
    ///   the total available if `output_options_slice` is too small or if the
    ///   remaining options data is not a multiple of 8 bytes.
    /// - `Err(HopOptError)`: If an error occurs during parsing, such as:
    ///     - `HopOptError::OutOfBounds`: If reading the initial part of the Hop-by-Hop header
    ///       (to access 'Hdr Ext Len') would go beyond `packet_end_ptr`.
    ///     - `HopOptError::UnexpectedEndOfPacket`: If the total length defined by
    ///       'Hdr Ext Len' extends beyond `packet_end_ptr`.
    pub unsafe fn parse_additional_options_to_u64_slice(
        header_ptr: *const HopOpt,
        packet_end_ptr: *const u8,
        output_opts_slice: &mut [u64],
    ) -> Result<usize, HopOptError> {
        // Ensure we can read at least hdr_ext_len.
        if (header_ptr as *const u8).add(2) > packet_end_ptr {
            return Err(HopOptError::OutOfBounds);
        }

        // Read hdr_ext_len.
        let num_opts_ptr = ptr::addr_of!((*header_ptr).hdr_ext_len);
        let num_opts_be = unsafe {ptr::read_unaligned(num_opts_ptr)};
        let hdr_ext_len_val = u8::from_be(num_opts_be) as usize;

        if hdr_ext_len_val == 0 {
            return Ok(0);
        }

        // Calculate total HBH header length and verify against packet boundaries.
        // Add 1 to cover the first octet of the Routing header
        let total_hbh_header_len = (hdr_ext_len_val as usize + 1) << 3;
        if (header_ptr as *const u8).add(total_hbh_header_len) > packet_end_ptr {
            return Err(HopOptError::UnexpectedEndOfPacket);
        }

        // Determine start and end pointers for "additional" options data.
        let mut current_opt_ptr = (header_ptr as *const u8).add(mem::size_of::<HopOpt>());
        let hbh_additional_opts_end_ptr = (header_ptr as *const u8).add(total_hbh_header_len);
        let mut options_packed_count: usize = 0;

        while current_opt_ptr < hbh_additional_opts_end_ptr {

            if options_packed_count >= output_opts_slice.len() {
                // Consider adding HopOptError for dst slice full
                break;
            }

            // Check if there are enough bytes remaining in THIS Hop-by-Hop header's additional options section
            // to read a full u64 (8 bytes). We must not read beyond hbh_additional_opts_end_ptr.
            if current_opt_ptr.add(mem::size_of::<u64>()) > hbh_additional_opts_end_ptr {
                // Consider adding HopOptError to signal leftover bytes
                break;
            }

            let mut packed_option_bytes = [0u8; 8];

            // Read 8 bytes (64 bits) from current_opt_ptr into packed_option_bytes.
            ptr::copy_nonoverlapping(
                current_opt_ptr,             // Source pointer from packet data
                packed_option_bytes.as_mut_ptr(), // Destination buffer
                mem::size_of::<u64>()        // Length to copy (8 bytes)
            );

            // Advance current_opt_ptr by the number of bytes read.
            current_opt_ptr = current_opt_ptr.add(mem::size_of::<u64>());

            // Convert the 8 bytes into a u64.
            output_opts_slice[options_packed_count] = u64::from_be_bytes(packed_option_bytes);
            options_packed_count += 1;
        }

        Ok(options_packed_count)
    }

}

#[cfg(test)]
mod tests {
    use super::*; // Imports HopOpt, HopOptError from the parent module

    // Helper to create a mutable HopOpt reference from a mutable byte array.
    // Assumes array is at least HopOpt::LEN (8 bytes) long.
    unsafe fn get_mut_hopopt_ref_from_array<const N: usize>(data: &mut [u8; N]) -> &mut HopOpt {
        assert!(N >= HopOpt::LEN, "Array too small to cast to HopOpt for testing");
        &mut *(data.as_mut_ptr() as *mut HopOpt)
    }

    // --- Tests for HopOpt struct's direct methods ---
    #[test]
    fn test_hopopt_getters_and_setters() {
        const BUF_SIZE: usize = HopOpt::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let hop_opt = unsafe { get_mut_hopopt_ref_from_array(&mut packet_buf) };

        hop_opt.set_nxt_hdr(58); // Example: ICMPv6
        assert_eq!(hop_opt.nxt_hdr(), 58);
        assert_eq!(hop_opt.nxt_hdr, 58);

        hop_opt.set_hdr_ext_len(1); // Example: Total HBH length would be (1+1)*8 = 16 bytes
        assert_eq!(hop_opt.hdr_ext_len(), 1);
        assert_eq!(hop_opt.hdr_ext_len, 1);

        hop_opt.opt_data[0] = 0xAA;
        hop_opt.opt_data[5] = 0xBB;
        let opt_data_slice = hop_opt.opt_data();
        assert_eq!(opt_data_slice[0], 0xAA);
        assert_eq!(opt_data_slice[5], 0xBB);
        assert_eq!(opt_data_slice.len(), 6);
    }

    #[test]
    fn test_hopopt_length_calculation_methods() {
        const BUF_SIZE: usize = HopOpt::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let hop_opt = unsafe { get_mut_hopopt_ref_from_array(&mut packet_buf) };

        hop_opt.set_hdr_ext_len(0);
        assert_eq!(hop_opt.total_hdr_len(), 8);
        assert_eq!(hop_opt.total_opts_len(), 6);

        hop_opt.set_hdr_ext_len(1);
        assert_eq!(hop_opt.total_hdr_len(), 16);
        assert_eq!(hop_opt.total_opts_len(), 14);

        hop_opt.set_hdr_ext_len(255); // Max value
        assert_eq!(hop_opt.total_hdr_len(), (255 + 1) * 8);
        assert_eq!(hop_opt.total_opts_len(), (255 + 1) * 8 - 2);
    }

    // --- Tests for parse_additional_options_to_u64_slice ---
    #[test]
    fn parse_additional_when_hdr_ext_len_is_zero() {
        const PACKET_SIZE: usize = HopOpt::LEN; // 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            59, 0, // nxt_hdr, hdr_ext_len = 0
            1, 2, 3, 4, 5, 6, // opt_data
        ];

        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn parse_additional_error_out_of_bounds_on_short_packet() {
        const PACKET_SIZE: usize = 1; // Packet too short for initial read of hdr_ext_len
        let packet_data: [u8; PACKET_SIZE] = [59];

        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Err(HopOptError::OutOfBounds));
    }

    #[test]
    fn parse_additional_error_unexpected_end_of_packet() {
        const PACKET_SIZE: usize = 8;
        // hdr_ext_len = 1 implies a 16-byte HBH header, but packet data is only 8 bytes.
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // nxt_hdr, hdr_ext_len = 1 (implies (1+1)*8 = 16 bytes total HBH)
            1, 2, 3, 4, 5, 6, // opt_data
        ];

        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Err(HopOptError::UnexpectedEndOfPacket));
    }

    #[test]
    fn parse_additional_one_chunk_exact_hbh_and_packet_length() {
        const PACKET_SIZE: usize = 16; // HBH is 16 bytes, additional options = 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // nxt_hdr, hdr_ext_len = 1 (total HBH 16 bytes)
            0, 0, 0, 0, 0, 0, // opt_data
            // Additional 8 bytes for one u64 
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];

        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(1));
        let expected_u64 = u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(output_slice[0], expected_u64);
    }

    #[test]
    fn parse_additional_multiple_chunks_exact_hbh_and_packet_length() {
        const PACKET_SIZE: usize = 24; // HBH is 24 bytes, additional options = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            59, 2, // nxt_hdr, hdr_ext_len = 2 (total HBH 24 bytes)
            0,0,0,0,0,0, // opt_data
            // Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 2];

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(2));
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22]));
        assert_eq!(output_slice[1], u64::from_be_bytes([0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00]));
    }

    #[test]
    fn parse_additional_output_slice_is_too_small() {
        const PACKET_SIZE: usize = 24; // HBH has 16 bytes of additional options (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            59, 2, 0,0,0,0,0,0,
            0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22, // Chunk 1
            0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00, // Chunk 2
        ];

        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1]; // Only space for one u64.

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(1));
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22]));
    }

    #[test]
    fn parse_additional_output_slice_is_empty() {
        const PACKET_SIZE: usize = 24; // HBH has 16 bytes of additional options
        let packet_data: [u8; PACKET_SIZE] = [
            59, 2, 0,0,0,0,0,0,
            0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22,
            0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
        ];
        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 0]; // Empty output slice.

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn parse_additional_stops_at_hbh_end_even_if_packet_is_longer() {
        // HBH header is declared as 16 bytes (hdr_ext_len=1).
        // So, its "additional options" are bytes 8-15 (1 chunk).
        // Packet data is 24 bytes long, containing more data after HBH defined end.
        const PACKET_SIZE: usize = 24;
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // nxt_hdr, hdr_ext_len = 1 (HBH total 16 bytes)
            0,0,0,0,0,0, // opt_data (bytes 0-7 of HBH struct)
            // Chunk 1 (bytes 8-15, this is the defined additional options for HBH)
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            // Trailing packet data (bytes 16-23), should be IGNORED by this function
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        ];

        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 2]; // Space for two u64s, but only one should be filled.

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        // Expected behavior using hbh_additional_opts_end_ptr for loop:
        // Loop Iteration 1:
        //    current_opt_ptr (8) < hbh_additional_opts_end_ptr (16). Output has space.
        //    current_opt_ptr.add(8) (16) is not > hbh_additional_opts_end_ptr (16). (16 <= 16).
        //    Reads bytes 8-15 (Chunk 1). current_opt_ptr becomes 16. options_packed_count = 1.
        // Loop Iteration 2:
        //    current_opt_ptr (16) < hbh_additional_opts_end_ptr (16) is false. Loop terminates.
        assert_eq!(result, Ok(1), "Should read only one chunk defined by HBH header, ignoring further packet data");
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA]));
        // output_slice[1] should remain untouched.
        if output_slice.len() > 1 {
            assert_eq!(output_slice[1], 0, "Second element of output_slice should be untouched");
        }
    }

    #[test]
    fn parse_additional_hbh_not_multiple_of_8_bytes() {
        // The HBH header length is always (N+1)*8.
        // The base HopOpt struct is 8 bytes.
        // So, additional_options_length = (N+1)*8 - 8 = N*8.
        // This means the additional options space is ALWAYS a multiple of 8 bytes if N > 0.
        // Therefore, the condition `current_opt_ptr.add(mem::size_of::<u64>()) > hbh_additional_opts_end_ptr`
        // will only cause a break if input ptrs are mal alligned or if the packet is not really
        // a HBH header
        const PACKET_SIZE: usize = 17; // HBH total 16 bytes (8 base + 9 improper additions)
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // hdr_ext_len = 1 -> 8 additional bytes
            0,0,0,0,0,0,
            1,2,3,4,5,6,7,8,9
        ];
        let header_ptr = packet_data.as_ptr() as *const HopOpt;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1]; // Expect one u64

        let result = unsafe {
            HopOpt::parse_additional_options_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(1)); // Reads the full 8 additional bytes.
        assert_eq!(output_slice[0], u64::from_be_bytes([1,2,3,4,5,6,7,8]));
    }
}
