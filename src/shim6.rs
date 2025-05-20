/// The Shim6 Control Header is a common header format used for various control messages within the Shim6 protocol. 
/// All Shim6 headers are designed to be a multiple of 8 octets in length, with a minimum size of 8 octets.
///
/// # Shim6 Control Message Header Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Header   | Hdr Ext Len   |P|      Type     |Type-specific|S|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                                                               |
/// .                     Type-specific format                      .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// ## Fields
///
/// * **Next Header (8 bits)**: An 8-bit selector. For Shim6 control messages, this field is 
/// normally set to `NO_NXT_HDR` (59), indicating that no further headers follow the Shim6 header.
///
/// * **Hdr Ext Len (8 bits)**: An 8-bit unsigned integer representing the length of the Shim6 
/// header in 8-octet (64-bit) units, **not including the first 8 octets** of the header. 
/// This field allows the receiver to determine the total length of the Shim6 header, including 
/// any variable-length type-specific data.
///
/// * **P (Payload Flag) (1 bit)**: A single bit that is always set to zero (`0`). This bit serves 
/// to distinguish the Shim6 Control Header from the Shim6 Payload Extension header.
///
/// * **Type (7 bits)**: A 7-bit unsigned integer that identifies the specific Shim6 control message 
/// type. Type codes 0-63 will **not** trigger R1bis messages (a specific error recovery mechanism in HIP) 
/// on a missing context, while codes 64-127 **will** trigger R1bis.
///
/// * **Type-specific (bits, part of a byte)**: A part of the header whose interpretation depends on 
/// the `Type` field. This is typically the first part of the `Type-specific format` after the `Type` 
/// field, sharing a byte with the `Type` and `S` fields.
///
/// * **S (Shim6/HIP Distinction) (1 bit)**: A single bit that is always set to zero (`0`). 
/// This bit allows Shim6 and HIP to share a common header format while still providing a mechanism 
/// to distinguish between Shim6 and HIP messages at a low level.
///
/// * **Checksum (16 bits)**: A 16-bit unsigned integer containing the checksum of the entire Shim6 
/// header message. The checksum is the 16-bit one's complement of the one's complement sum of the 
/// octet string starting with the `Next Header` field and ending as indicated by the `Hdr Ext Len` field.
///
/// * **Type-specific format (variable length)**: This is a variable-length portion of the header 
/// whose structure and content are entirely dependent on the specific `Type` of the Shim6 message. 
/// It follows the fixed initial fields and is included in the `Hdr Ext Len` calculation.

use crate::chunk_reader;
use core::mem;

const TYPE_SPECIFIC_CHUNK_LEN: usize = mem::size_of::<u64>();

/// Common Shim6 Control header structure
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Shim6Hdr {
    /// Next Header field (8 bits)
    pub next_hdr: u8,
    /// Header Length field (8 bits)
    pub hdr_len: u8,
    /// P bit distinguishing from Shim6 Payload Extension Header (1 bit) + Packet Type (7 bits)
    pub p_type_: u8,
    /// Type-specific information (7 bits) + S bit distinguishing from HIP message type
    pub type_s: u8,
    /// Checksum field (16 bits)
    pub checksum: [u8; 2],
    /// Start of Type-Specific data, should be 0 if hdr_len is 0.
    pub type_specific: [u8; 2],
}

impl Shim6Hdr {
    /// The total size in bytes of the fixed part of the Shim6 Header
    pub const LEN: usize = mem::size_of::<Shim6Hdr>();

    /// Gets the Next Header value.
    pub fn next_hdr(&self) -> u8 {
        self.next_hdr
    }

    /// Sets the Next Header value.
    pub fn set_next_hdr(&mut self, next_hdr: u8) {
        self.next_hdr = next_hdr;
    }

    /// Gets the Header Length value.
    /// This value is the length of the Shim6 Header in 8-octet units, not including the first 8 octets.
    pub fn hdr_len(&self) -> u8 {
        self.hdr_len
    }

    /// Sets the Header Length value.
    pub fn set_hdr_len(&mut self, hdr_len: u8) {
        self.hdr_len = hdr_len;
    }

    /// Gets the P (Payload Flag) bit.
    /// This bit is always set to zero (0) for Shim6 Control Headers.
    pub fn p_flag(&self) -> bool {
        (self.p_type_ & 0x80) != 0
    }

    /// Sets the P (Payload Flag) bit.
    /// This bit should be set to zero (0) for Shim6 Control Headers.
    pub fn set_p_flag(&mut self, p_flag: bool) {
        if p_flag {
            self.p_type_ |= 0x80;
        } else {
            self.p_type_ &= 0x7F;
        }
    }

    /// Gets the Type value (7 bits).
    pub fn type_(&self) -> u8 {
        self.p_type_ & 0x7F
    }

    /// Sets the Type value (7 bits).
    pub fn set_type(&mut self, type_: u8) {
        // Preserve the P flag bit
        let p_flag = self.p_type_ & 0x80;
        // Clear the type bits and set the new type value
        self.p_type_ = p_flag | (type_ & 0x7F);
    }

    /// Gets the Type-specific value (7 bits) from the type_s field.
    pub fn type_specific(&self) -> u8 {
        self.type_s >> 1
    }

    /// Sets the Type-specific value (7 bits) in the type_s field.
    pub fn set_type_specific(&mut self, type_specific: u8) {
        // Preserve the S bit
        let s_bit = self.type_s & 0x01;
        // Clear the type-specific bits and set the new value
        self.type_s = (type_specific << 1) | s_bit;
    }

    /// Gets the Type-specific data as a 16-bit value.
    pub fn type_specific_data(&self) -> u16 {
        u16::from_be_bytes(self.type_specific)
    }

    /// Sets the Type-specific data from a 16-bit value.
    pub fn set_type_specific_data(&mut self, type_specific_data: u16) {
        self.type_specific = type_specific_data.to_be_bytes();
    }

    /// Gets the S (Shim6/HIP Distinction) bit.
    /// This bit is always set to zero (0) for Shim6 messages.
    pub fn s_bit(&self) -> bool {
        (self.type_s & 0x01) != 0
    }

    /// Sets the S (Shim6/HIP Distinction) bit.
    /// This bit should be set to zero (0) for Shim6 messages.
    pub fn set_s_bit(&mut self, s_bit: bool) {
        if s_bit {
            self.type_s |= 0x01;
        } else {
            self.type_s &= 0xFE;
        }
    }

    /// Gets the Checksum value as a 16-bit value.
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the Checksum value from a 16-bit value.
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Calculates the total length of the Shim6 Header in bytes.
    /// The Header Length is in 8-octet units, not including the first 8 octets.
    /// So, total length = (hdr_len << 3) + 8, where << 3 is equivalent to * 8 but more efficient.
    pub fn total_hdr_len(&self) -> usize {
        ((self.hdr_len as usize) << 3) + 8
    }

    /// Calculates the length of the Type-specific format data in bytes.
    /// Type-specific format length = Total Header Length - Fixed Header Length.
    pub fn type_specific_len(&self) -> usize {
        if self.hdr_len == 0 {
            0
        } else {
            self.total_hdr_len().saturating_sub(Shim6Hdr::LEN)
        }
    }

    /// Extracts the variable-length Type-specific format data from the Shim6 Header
    /// into a caller-provided slice of `u64`.
    ///
    /// The Shim6 Header's `hdr_len` field determines the total length of
    /// the Shim6 header, from which the length of the Type-specific format data is derived.
    /// The Type-specific format data is the data that follows the fixed part of the Shim6 Header.
    /// This function reads the Type-specific format data in 8-byte (u64) chunks.
    ///
    /// # Safety
    /// This method is unsafe because it performs raw pointer arithmetic and memory access.
    /// The caller must ensure:
    /// - The Shim6Hdr instance points to valid memory containing a complete Shim6 Header
    /// - The memory region from the Shim6Hdr through the end of the Type-specific format data is valid and accessible
    /// - The total length calculated from hdr_len does not exceed available memory bounds
    ///
    /// # Arguments
    /// - `buffer`: A mutable slice of `u64` where the parsed Type-specific format data will be
    ///   written. Data is read from the packet (assumed to be in network byte order)
    ///   and converted to `u64` values in host byte order.
    ///
    /// # Returns
    /// A Result containing:
    /// - Ok(usize): The number of complete u64 words successfully read from the Type-specific format data and written
    ///   to `buffer`. This may be:
    ///   - 0 if no Type-specific format data is present (`total_hdr_len` <= `Shim6Hdr::LEN`)
    ///   - Less than the total available Type-specific format data if:
    ///     - `buffer` is too small to hold all Type-specific format data words
    ///     - The remaining Type-specific format data bytes are not enough for a complete u64 word
    /// - Err(ChunkReaderError): If an error occurred during reading, such as:
    ///   - UnexpectedEndOfPacket: If the packet data ends unexpectedly
    ///   - InvalidChunkLength: If the chunk length is not equal to the size of u64
    pub unsafe fn type_specific_buffer(&self, buffer: &mut [u64]) -> Result<usize, chunk_reader::ChunkReaderError> {
        let self_ptr: *const Shim6Hdr = self;
        let self_ptr_u8: *const u8 = self_ptr as *const u8;
        let total_hdr_len = self.total_hdr_len();
        let start_data_ptr = (self_ptr_u8).add(Shim6Hdr::LEN);
        let end_data_ptr = (self_ptr_u8).add(total_hdr_len);

        if total_hdr_len <= Shim6Hdr::LEN {
            return Ok(0);
        }

        chunk_reader::read_chunks(start_data_ptr, end_data_ptr, buffer, TYPE_SPECIFIC_CHUNK_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim6hdr_size() {
        // The Shim6Hdr structure should be 8 bytes in size (including the type_specific field)
        assert_eq!(Shim6Hdr::LEN, 8);
    }

    // Helper to create a mutable Shim6Hdr reference from a mutable byte array.
    unsafe fn get_mut_shim6hdr_ref_from_array<const N: usize>(data: &mut [u8; N]) -> &mut Shim6Hdr {
        assert!(
            N >= Shim6Hdr::LEN,
            "Array too small to cast to Shim6Hdr for testing"
        );
        &mut *(data.as_mut_ptr() as *mut Shim6Hdr)
    }

    #[test]
    fn test_shim6hdr_getters_and_setters() {
        const BUF_SIZE: usize = Shim6Hdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let shim6_hdr = unsafe { get_mut_shim6hdr_ref_from_array(&mut packet_buf) };

        // Test next_hdr
        shim6_hdr.set_next_hdr(59); // Example: No Next Header
        assert_eq!(shim6_hdr.next_hdr(), 59);
        assert_eq!(shim6_hdr.next_hdr, 59);

        // Test hdr_len
        shim6_hdr.set_hdr_len(2); // Example: 2 additional 8-octet units
        assert_eq!(shim6_hdr.hdr_len(), 2);
        assert_eq!(shim6_hdr.hdr_len, 2);

        // Test p_flag
        shim6_hdr.set_p_flag(false); // Should be 0 for Shim6 Control Headers
        assert_eq!(shim6_hdr.p_flag(), false);
        assert_eq!(shim6_hdr.p_type_ & 0x80, 0);

        // Test type_
        shim6_hdr.set_type(64); // Example: Type 64
        assert_eq!(shim6_hdr.type_(), 64);
        assert_eq!(shim6_hdr.p_type_ & 0x7F, 64);

        // Test type_specific
        shim6_hdr.set_type_specific(42); // Example: Type-specific value 42
        assert_eq!(shim6_hdr.type_specific(), 42);
        assert_eq!(shim6_hdr.type_s >> 1, 42);

        // Test s_bit
        shim6_hdr.set_s_bit(false); // Should be 0 for Shim6 messages
        assert_eq!(shim6_hdr.s_bit(), false);
        assert_eq!(shim6_hdr.type_s & 0x01, 0);

        // Test checksum
        shim6_hdr.set_checksum(0xABCD);
        assert_eq!(shim6_hdr.checksum(), 0xABCD);
        assert_eq!(shim6_hdr.checksum, [0xAB, 0xCD]);

        // Test type_specific_data
        shim6_hdr.set_type_specific_data(0x1234);
        assert_eq!(shim6_hdr.type_specific_data(), 0x1234);
        assert_eq!(shim6_hdr.type_specific, [0x12, 0x34]);
    }

    #[test]
    fn test_shim6hdr_length_calculation_methods() {
        const BUF_SIZE: usize = Shim6Hdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let shim6_hdr = unsafe { get_mut_shim6hdr_ref_from_array(&mut packet_buf) };

        // Test with hdr_len = 0
        shim6_hdr.set_hdr_len(0);
        assert_eq!(shim6_hdr.total_hdr_len(), 8);
        assert_eq!(shim6_hdr.type_specific_len(), 0);

        // Test with hdr_len = 1
        shim6_hdr.set_hdr_len(1);
        assert_eq!(shim6_hdr.total_hdr_len(), 16);
        // Calculate the expected type_specific_len based on the actual Shim6Hdr::LEN
        let expected_type_specific_len = 16 - Shim6Hdr::LEN;
        assert_eq!(shim6_hdr.type_specific_len(), expected_type_specific_len);

        // Test with hdr_len = 2
        shim6_hdr.set_hdr_len(2);
        assert_eq!(shim6_hdr.total_hdr_len(), 24);
        // Calculate the expected type_specific_len based on the actual Shim6Hdr::LEN
        let expected_type_specific_len = 24 - Shim6Hdr::LEN;
        assert_eq!(shim6_hdr.type_specific_len(), expected_type_specific_len);

        // Test with hdr_len = 255 (max value)
        shim6_hdr.set_hdr_len(255);
        assert_eq!(shim6_hdr.total_hdr_len(), (255 * 8) + 8);
        assert_eq!(shim6_hdr.type_specific_len(), (255 * 8) + 8 - Shim6Hdr::LEN);
    }

    #[test]
    fn test_extract_type_specific_when_hdr_len_is_zero() {
        const PACKET_SIZE: usize = 8; // Shim6Hdr is 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            59, 0, // next_hdr, hdr_len = 0
            0, 0, // p_type_, type_s
            0xAB, 0xCD, // checksum
            0, 0, // Padding to match PACKET_SIZE
        ];

        let shim6_hdr = unsafe { &*(packet_data.as_ptr() as *const Shim6Hdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { shim6_hdr.type_specific_buffer(&mut output_slice) };
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_extract_type_specific_one_chunk_exact() {
        const PACKET_SIZE: usize = 16; // Shim6Hdr is 8 bytes, Type-specific = 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            59, 1, // next_hdr, hdr_len = 1 (total 16 bytes)
            0x40, 0x54, // p_type_ = 64, type_s = 84 (type_specific = 42, s_bit = 0)
            0xAB, 0xCD, // checksum
            0, 0, // Padding to align with 8-byte boundary
            // Type-specific format data (8 bytes)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];

        let shim6_hdr = unsafe { &*(packet_data.as_ptr() as *const Shim6Hdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { shim6_hdr.type_specific_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1));
        let expected_u64 = u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(output_slice[0], expected_u64);
    }

    #[test]
    fn test_extract_type_specific_multiple_chunks() {
        const PACKET_SIZE: usize = 24; // Shim6Hdr is 8 bytes, Type-specific = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            59, 2, // next_hdr, hdr_len = 2 (total 24 bytes)
            0x40, 0x54, // p_type_ = 64, type_s = 84 (type_specific = 42, s_bit = 0)
            0xAB, 0xCD, // checksum
            0, 0, // Padding to align with 8-byte boundary
            // Type-specific Chunk 1 (8 bytes)
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Type-specific Chunk 2 (8 bytes)
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let shim6_hdr = unsafe { &*(packet_data.as_ptr() as *const Shim6Hdr) };
        let mut output_slice = [0u64; 2];

        let result = unsafe { shim6_hdr.type_specific_buffer(&mut output_slice) };
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
    fn test_extract_type_specific_output_slice_is_too_small() {
        const PACKET_SIZE: usize = 24; // Shim6Hdr is 8 bytes, Type-specific = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            59, 2, // next_hdr, hdr_len = 2 (total 24 bytes)
            0x40, 0x54, // p_type_ = 64, type_s = 84 (type_specific = 42, s_bit = 0)
            0xAB, 0xCD, // checksum
            0, 0, // Padding to align with 8-byte boundary
            // Type-specific Chunk 1 (8 bytes)
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Type-specific Chunk 2 (8 bytes)
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let shim6_hdr = unsafe { &*(packet_data.as_ptr() as *const Shim6Hdr) };
        let mut output_slice = [0u64; 1]; // Only space for one u64.

        let result = unsafe { shim6_hdr.type_specific_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1));
        assert_eq!(
            output_slice[0],
            u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])
        );
    }

    #[test]
    fn test_type_specific_buffer_corrupt_header_len() {
        const PACKET_SIZE: usize = 12; // Shim6Hdr should be 16 bytes but we only provide 12
        let packet_data: [u8; PACKET_SIZE] = [
            59, 0, // next_hdr, hdr_len = 1 (total 16 bytes)
            0x40, 0x54, // p_type_ = 64, type_s = 84 (type_specific = 42, s_bit = 0)
            0xAB, 0xCD, // checksum
            0, 0, // type_specific
            // Only 4 bytes of the expected 8 bytes of type-specific data
            0x11, 0x22, 0x33, 0x44,
        ];

        let shim6_hdr = unsafe { &*(packet_data.as_ptr() as *const Shim6Hdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { shim6_hdr.type_specific_buffer(&mut output_slice) };
        assert_eq!(result, Ok(0));
    }
}
