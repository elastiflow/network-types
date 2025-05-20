use crate::chunk_reader;
use core::mem;

/// IPv6 Hop-by-Hop Options Extension Header
///
/// This struct can also be used to represent IPv6 Destination Options Extension Header
/// as both headers share the same format. The only difference is in the Next Header value
/// and their position in the IPv6 extension header chain.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct HopOptHdr {
    pub next_hdr: u8,
    pub hdr_ext_len: u8,
    /// The first 6 bytes of the options field.
    /// If hdr_ext_len is 0, these are all the options.
    /// If hdr_ext_len > 0, additional options follow these 6 bytes.
    pub opt_data: [u8; 6], // These 6 octets options are always present
}

const HOP_OPT_CHUNK_LEN: usize = mem::size_of::<u64>();

impl HopOptHdr {
    /// The total size in bytes of default length HbH header
    pub const LEN: usize = mem::size_of::<HopOptHdr>();

    /// Gets the Next Header value.
    pub fn next_hdr(&self) -> u8 {
        self.next_hdr
    }

    /// Sets the Next Header value.
    pub fn set_next_hdr(&mut self, next_hdr: u8) {
        self.next_hdr = next_hdr;
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
    /// Options field = Total Header Length - 2 bytes (for next_hdr and hdr_ext_len).
    pub fn total_opts_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(2)
    }

    /// Parses Hop-by-Hop options from the variable-length options field of a Hop-by-Hop
    /// Options header into a caller-provided slice of u64.
    ///
    /// This function reads the options data that follows the initial 8-byte fixed header
    /// of the Hop-by-Hop Options header. The length of the additional options data is
    /// determined by the 'Hdr Ext Len' field. Options are read in 8-byte (u64) chunks.
    /// This function is intended for scenarios where options or their data are aligned
    /// and can be meaningfully interpreted as u64 values.
    ///
    /// # Safety
    /// The memory region covered by the Hop-by-Hop Options header, as determined by its
    /// 'Hdr Ext Len' field (i.e., `(hdr_ext_len_value + 1) * 8` bytes), must be valid
    /// and accessible memory.
    ///
    /// # Arguments
    /// - `opt_buffer`: A mutable slice of `u64` where the parsed options data will be
    ///   written. Data is read from the packet (assumed to be in network byte order)
    ///   and converted to `u64` values (host byte order).
    ///
    /// # Returns
    /// A Result containing:
    /// - Ok(usize): The number of complete u64 words successfully read from the additional options
    ///   and written to `opt_buffer`. This may be:
    ///   - 0 if no additional options data is present (`total_hdr_len` <= `HopOptHdr::LEN`)
    ///   - Less than the total available additional options data if:
    ///     - `opt_buffer` is too small to hold all additional options words
    ///     - The remaining additional options bytes are not enough for a complete u64 word
    /// - Err(ChunkReaderError): If an error occurred during reading, such as:
    ///   - UnexpectedEndOfPacket: If the packet data ends unexpectedly
    ///   - InvalidChunkLength: If the chunk length is not equal to the size of u64
    pub unsafe fn opt_buffer(&self, opt_buffer: &mut [u64]) -> Result<usize, chunk_reader::ChunkReaderError> {
        let self_ptr: *const HopOptHdr = self;
        let self_ptr_u8: *const u8 = self_ptr as *const u8;
        let total_hdr_len = self.total_hdr_len();
        let start_data_ptr = (self_ptr_u8).add(HopOptHdr::LEN);
        let end_data_ptr = (self_ptr_u8).add(total_hdr_len);
        if total_hdr_len <= HopOptHdr::LEN {
            return Ok(0);
        }

        chunk_reader::read_chunks(start_data_ptr, end_data_ptr, opt_buffer, HOP_OPT_CHUNK_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Imports HopOpt, HopOptError from the parent module

    // Helper to create a mutable HopOpt reference from a mutable byte array.
    // Assumes array is at least HopOpt::LEN (8 bytes) long.
    unsafe fn get_mut_hopopt_ref_from_array<const N: usize>(data: &mut [u8; N]) -> &mut HopOptHdr {
        assert!(
            N >= HopOptHdr::LEN,
            "Array too small to cast to HopOpt for testing"
        );
        &mut *(data.as_mut_ptr() as *mut HopOptHdr)
    }

    // --- Tests for HopOpt struct's direct methods ---
    #[test]
    fn test_hopopt_getters_and_setters() {
        const BUF_SIZE: usize = HopOptHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let hop_opt = unsafe { get_mut_hopopt_ref_from_array(&mut packet_buf) };

        hop_opt.set_next_hdr(58); // Example: ICMPv6
        assert_eq!(hop_opt.next_hdr(), 58);
        assert_eq!(hop_opt.next_hdr, 58);

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
        const BUF_SIZE: usize = HopOptHdr::LEN;
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
        const PACKET_SIZE: usize = HopOptHdr::LEN; // 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            59, 0, // next_hdr, hdr_ext_len = 0
            1, 2, 3, 4, 5, 6, // opt_data
        ];

        let hop_opt_hdr = unsafe { &*(packet_data.as_ptr() as *const HopOptHdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { hop_opt_hdr.opt_buffer(&mut output_slice) };
        assert_eq!(result, Ok(0));
    }

    // This test is no longer needed as the function now takes &self and doesn't check for out of bounds

    // This test is no longer needed as the function now takes &self and doesn't check for unexpected end of packet

    #[test]
    fn parse_additional_one_chunk_exact_hbh_and_packet_length() {
        const PACKET_SIZE: usize = 16; // HBH is 16 bytes, additional options = 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // next_hdr, hdr_ext_len = 1 (total HBH 16 bytes)
            0, 0, 0, 0, 0, 0, // opt_data
            // Additional 8 bytes for one u64
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];

        let hop_opt_hdr = unsafe { &*(packet_data.as_ptr() as *const HopOptHdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { hop_opt_hdr.opt_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1));
        let expected_u64 = u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(output_slice[0], expected_u64);
    }

    #[test]
    fn parse_additional_multiple_chunks_exact_hbh_and_packet_length() {
        const PACKET_SIZE: usize = 24; // HBH is 24 bytes, additional options = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            59, 2, // next_hdr, hdr_ext_len = 2 (total HBH 24 bytes)
            0, 0, 0, 0, 0, 0, // opt_data
            // Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let hop_opt_hdr = unsafe { &*(packet_data.as_ptr() as *const HopOptHdr) };
        let mut output_slice = [0u64; 2];

        let result = unsafe { hop_opt_hdr.opt_buffer(&mut output_slice) };
        assert_eq!(result, Ok(2));
        assert_eq!(
            output_slice[0],
            u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])
        );
        assert_eq!(
            output_slice[1],
            u64::from_be_bytes([0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00])
        );
    }

    #[test]
    fn parse_additional_output_slice_is_too_small() {
        const PACKET_SIZE: usize = 24; // HBH has 16 bytes of additional options (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            59, 2, 0, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11,
            0x22, // Chunk 1
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, // Chunk 2
        ];

        let hop_opt_hdr = unsafe { &*(packet_data.as_ptr() as *const HopOptHdr) };
        let mut output_slice = [0u64; 1]; // Only space for one u64.

        let result = unsafe { hop_opt_hdr.opt_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1));
        assert_eq!(
            output_slice[0],
            u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])
        );
    }

    #[test]
    fn parse_additional_output_slice_is_empty() {
        const PACKET_SIZE: usize = 24; // HBH has 16 bytes of additional options
        let packet_data: [u8; PACKET_SIZE] = [
            59, 2, 0, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];
        let hop_opt_hdr = unsafe { &*(packet_data.as_ptr() as *const HopOptHdr) };
        let mut output_slice = [0u64; 0]; // Empty output slice.

        let result = unsafe { hop_opt_hdr.opt_buffer(&mut output_slice) };
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn parse_additional_stops_at_hbh_end_even_if_packet_is_longer() {
        // HBH header is declared as 16 bytes (hdr_ext_len=1).
        // So, its "additional options" are bytes 8-15 (1 chunk).
        // Packet data is 24 bytes long, containing more data after HBH defined end.
        const PACKET_SIZE: usize = 24;
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // next_hdr, hdr_ext_len = 1 (HBH total 16 bytes)
            0, 0, 0, 0, 0, 0, // opt_data (bytes 0-7 of HBH struct)
            // Chunk 1 (bytes 8-15, this is the defined additional options for HBH)
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            // Trailing packet data (bytes 16-23), should be IGNORED by this function
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        ];

        let hop_opt_hdr = unsafe { &*(packet_data.as_ptr() as *const HopOptHdr) };
        let mut output_slice = [0u64; 2]; // Space for two u64s, but only one should be filled.

        let result = unsafe { hop_opt_hdr.opt_buffer(&mut output_slice) };
        // Expected behavior using opts_end_ptr for loop:
        // Loop Iteration 1:
        //    current_opt_ptr (8) < opts_end_ptr (16). Output has space.
        //    current_opt_ptr.add(8) (16) is not > opts_end_ptr (16). (16 <= 16).
        //    Reads bytes 8-15 (Chunk 1). current_opt_ptr becomes 16. options_packed_count = 1.
        // Loop Iteration 2:
        //    current_opt_ptr (16) < opts_end_ptr (16) is false. Loop terminates.
        assert_eq!(
            result, Ok(1),
            "Should read only one chunk defined by HBH header, ignoring further packet data"
        );
        assert_eq!(
            output_slice[0],
            u64::from_be_bytes([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA])
        );
        // output_slice[1] should remain untouched.
        if output_slice.len() > 1 {
            assert_eq!(
                output_slice[1], 0,
                "Second element of output_slice should be untouched"
            );
        }
    }

    #[test]
    fn parse_additional_hbh_not_multiple_of_8_bytes() {
        // The HBH header length is always (N+1)*8.
        // The base HopOpt struct is 8 bytes.
        // So, additional_options_length = (N+1)*8 - 8 = N*8.
        // This means the additional options space is ALWAYS a multiple of 8 bytes if N > 0.
        // Therefore, the condition `current_opt_ptr.add(mem::size_of::<u64>()) > opts_end_ptr`
        // will only cause a break if input ptrs are mal alligned or if the packet is not really
        // a HBH header
        const PACKET_SIZE: usize = 17; // HBH total 16 bytes (8 base + 9 improper additions)
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // hdr_ext_len = 1 -> 8 additional bytes
            0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        ];
        let hop_opt_hdr = unsafe { &*(packet_data.as_ptr() as *const HopOptHdr) };
        let mut output_slice = [0u64; 1]; // Expect one u64

        let result = unsafe { hop_opt_hdr.opt_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1)); // Reads the full 8 additional bytes.
        assert_eq!(
            output_slice[0],
            u64::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8])
        );
    }

    #[test]
    fn parse_additional_unexpected_end_of_packet() {
        // Create a packet with hdr_ext_len = 1 (total 16 bytes) but only provide 12 bytes
        // This should cause an UnexpectedEndOfPacket error
        const PACKET_SIZE: usize = 12; // HBH should be 16 bytes but we only provide 12
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // next_hdr, hdr_ext_len = 1 (total HBH 16 bytes)
            0, 0, 0, 0, 0, 0, // opt_data
            // Only 4 bytes of the expected 8 bytes of additional options
            0x11, 0x22, 0x33, 0x44, // next packet 0x55, 0x66 
        ];
        

        let hop_opt_hdr = unsafe { &*(packet_data.as_ptr() as *const HopOptHdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { hop_opt_hdr.opt_buffer(&mut output_slice) };
        match result {
            Err(chunk_reader::ChunkReaderError::UnexpectedEndOfPacket { bytes_read, count }) => {
                assert_eq!(bytes_read, 0);
                assert_eq!(count, 0);
            }
            _ => panic!("Expected UnexpectedEndOfPacket error, got {:?}", result),
        }
    }
}
