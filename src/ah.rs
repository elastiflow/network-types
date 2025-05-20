use crate::chunk_reader;
use core::mem;

/// # Authentication Header Format
///
/// | Offset | Octet 0       | Octet 1       | Octet 2       | Octet 3       |
/// |--------|---------------|---------------|---------------|---------------|
/// | 0      | Next Header   | Payload Len   | Reserved (bits 0-7) | Reserved (bits 8-15) |
/// | 4      | Security Parameters Index (bits 0-7) | Security Parameters Index (bits 8-15) | Security Parameters Index (bits 16-23) | Security Parameters Index (bits 24-31) |
/// | 8      | Sequence Number (bits 0-7) | Sequence Number (bits 8-15) | Sequence Number (bits 16-23) | Sequence Number (bits 24-31) |
/// | 12     | Integrity Check Value (variable length, multiple of 32 bits) |
/// | ⋮      | ⋮             |
///
/// ## Fields
///
/// * **Next Header (8 bits)**: Identifies the type of the next header,
/// * **Payload Len (8 bits)**: The length of this Authentication Header in 4-octet units,
/// * **Reserved (16 bits)**: Reserved for future use and initialized to all zeroes.
/// * **Security Parameters Index (32 bits)**: Identifies the security association of the receiving party.
/// * **Sequence Number (32 bits)**: A monotonic, strictly increasing sequence number to prevent replay attacks.
/// * **Integrity Check Value (multiple of 32 bits)**: A variable-length check value.
/// Authentication Header
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AhHdr {
    pub next_hdr: u8,
    pub payload_len: u8,
    pub reserved: [u8; 2],
    pub spi: [u8; 4],
    pub seq_num: [u8; 4],
}

const ICV_CHUNK_LEN: usize = mem::size_of::<u64>();

impl AhHdr {
    /// The total size in bytes of the fixed part of the Authentication Header
    pub const LEN: usize = mem::size_of::<AhHdr>();

    /// Gets the Next Header value.
    pub fn next_hdr(&self) -> u8 {
        self.next_hdr
    }

    /// Sets the Next Header value.
    pub fn set_next_hdr(&mut self, next_hdr: u8) {
        self.next_hdr = next_hdr;
    }

    /// Gets the Payload Length value.
    /// This value is the length of the Authentication Header in 4-octet units, minus 2.
    pub fn payload_len(&self) -> u8 {
        self.payload_len
    }

    /// Sets the Payload Length value.
    pub fn set_payload_len(&mut self, payload_len: u8) {
        self.payload_len = payload_len;
    }

    /// Gets the Reserved field as a 16-bit value.
    pub fn reserved(&self) -> u16 {
        u16::from_be_bytes(self.reserved)
    }

    /// Sets the Reserved field from a 16-bit value.
    pub fn set_reserved(&mut self, reserved: u16) {
        self.reserved = reserved.to_be_bytes();
    }

    /// Gets the Security Parameters Index as a 32-bit value.
    pub fn spi(&self) -> u32 {
        u32::from_be_bytes(self.spi)
    }

    /// Sets the Security Parameters Index from a 32-bit value.
    pub fn set_spi(&mut self, spi: u32) {
        self.spi = spi.to_be_bytes();
    }

    /// Gets the Sequence Number as a 32-bit value.
    pub fn seq_num(&self) -> u32 {
        u32::from_be_bytes(self.seq_num)
    }

    /// Sets the Sequence Number from a 32-bit value.
    pub fn set_seq_num(&mut self, seq_num: u32) {
        self.seq_num = seq_num.to_be_bytes();
    }

    /// Calculates the total length of the Authentication Header in bytes.
    /// The Payload Length is in 4-octet units, minus 2.
    /// So, total length = (payload_len + 2) * 4.
    pub fn total_hdr_len(&self) -> usize {
        (self.payload_len as usize + 2) << 2
    }

    /// Calculates the length of the Integrity Check Value in bytes.
    /// ICV length = Total Header Length - Fixed Header Length.
    pub fn icv_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(AhHdr::LEN)
    }

    /// Extracts the variable-length Integrity Check Value (ICV) from the Authentication Header
    /// into a caller-provided slice of `u64`.
    ///
    /// The Authentication Header's `payload_len` field determines the total length of
    /// the AH header, from which the length of the ICV is derived. The ICV is the
    /// data that follows the fixed part of the Authentication Header. This function
    /// reads the ICV data in 8-byte (u64) chunks.
    ///
    /// # Safety
    /// This method is unsafe because it performs raw pointer arithmetic and memory access.
    /// The caller must ensure:
    /// - The AhHdr instance points to valid memory containing a complete Authentication Header
    /// - The memory region from the AhHdr through the end of the ICV is valid and accessible
    /// - The total length calculated from payload_len does not exceed available memory bounds
    ///
    /// # Arguments
    /// - `icv_buffer`: A mutable slice of `u64` where the parsed ICV will be
    ///   written. Data is read from the packet (assumed to be in network byte order)
    ///   and converted to `u64` values in host byte order.
    ///
    /// # Returns
    /// A Result containing:
    /// - Ok(usize): The number of complete u64 words successfully read from the ICV and written
    ///   to `icv_buffer`. This may be:
    ///   - 0 if no ICV data is present (`total_hdr_len` <= `AuthHdr::LEN`)
    ///   - Less than the total available ICV data if `icv_buffer` is too small to hold all ICV words
    /// - Err(ChunkReaderError): If an error occurred during reading:
    ///   - UnexpectedEndOfPacket: If the packet data ends unexpectedly before a complete chunk
    ///   - InvalidChunkLength: If ICV_CHUNK_LEN is not equal to the size of u64
    pub unsafe fn icv_buffer(&self, icv_buffer: &mut [u64]) -> Result<usize, chunk_reader::ChunkReaderError> {
        let self_ptr: *const AhHdr = self;
        let self_ptr_u8: *const u8 = self_ptr as *const u8;
        let total_hdr_len = self.total_hdr_len();
        let start_data_ptr = (self_ptr_u8).add(AhHdr::LEN);
        let end_data_ptr = (self_ptr_u8).add(total_hdr_len);

        if total_hdr_len <= AhHdr::LEN {
            return Ok(0);
        }

        chunk_reader::read_chunks(start_data_ptr, end_data_ptr, icv_buffer, ICV_CHUNK_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_reader::ChunkReaderError;

    // Helper to create a mutable AhHdr reference from a mutable byte array.
    unsafe fn get_mut_ahhdr_ref_from_array<const N: usize>(data: &mut [u8; N]) -> &mut AhHdr {
        assert!(
            N >= AhHdr::LEN,
            "Array too small to cast to ahhdr for testing"
        );
        &mut *(data.as_mut_ptr() as *mut AhHdr)
    }

    #[test]
    fn test_ahhdr_getters_and_setters() {
        const BUF_SIZE: usize = AhHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let auth_hdr = unsafe { get_mut_ahhdr_ref_from_array(&mut packet_buf) };

        // Test next_hdr
        auth_hdr.set_next_hdr(6); // Example: TCP
        assert_eq!(auth_hdr.next_hdr(), 6);
        assert_eq!(auth_hdr.next_hdr, 6);

        // Test payload_len
        auth_hdr.set_payload_len(4); // Example: Total length would be (4+2)*4 = 24 bytes
        assert_eq!(auth_hdr.payload_len(), 4);
        assert_eq!(auth_hdr.payload_len, 4);

        // Test reserved
        auth_hdr.set_reserved(0x1234);
        assert_eq!(auth_hdr.reserved(), 0x1234);
        assert_eq!(auth_hdr.reserved, [0x12, 0x34]);

        // Test spi
        auth_hdr.set_spi(0x12345678);
        assert_eq!(auth_hdr.spi(), 0x12345678);
        assert_eq!(auth_hdr.spi, [0x12, 0x34, 0x56, 0x78]);

        // Test seq_num
        auth_hdr.set_seq_num(0x87654321);
        assert_eq!(auth_hdr.seq_num(), 0x87654321);
        assert_eq!(auth_hdr.seq_num, [0x87, 0x65, 0x43, 0x21]);
    }

    #[test]
    fn test_ahhdr_length_calculation_methods() {
        const BUF_SIZE: usize = AhHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let auth_hdr = unsafe { get_mut_ahhdr_ref_from_array(&mut packet_buf) };

        // Test with payload_len = 0
        auth_hdr.set_payload_len(0);
        assert_eq!(auth_hdr.total_hdr_len(), 8);
        assert_eq!(auth_hdr.icv_len(), 0);

        // Test with payload_len = 1
        auth_hdr.set_payload_len(1);
        assert_eq!(auth_hdr.total_hdr_len(), 12);
        assert_eq!(auth_hdr.icv_len(), 0);

        // Test with payload_len = 3
        auth_hdr.set_payload_len(3);
        assert_eq!(auth_hdr.total_hdr_len(), 20);
        assert_eq!(auth_hdr.icv_len(), 8);

        // Test with payload_len = 255 (max value)
        auth_hdr.set_payload_len(255);
        assert_eq!(auth_hdr.total_hdr_len(), (255 + 2) * 4);
        assert_eq!(auth_hdr.icv_len(), (255 + 2) * 4 - AhHdr::LEN);
    }

    #[test]
    fn test_extract_icv_when_payload_len_is_zero() {
        const PACKET_SIZE: usize = AhHdr::LEN; // 12 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            6, 0, // next_hdr, payload_len = 0
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
        ];

        let auth_hdr = unsafe { &*(packet_data.as_ptr() as *const AhHdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { auth_hdr.icv_buffer(&mut output_slice) };
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_extract_icv_one_chunk_exact_ah_and_packet_length() {
        const PACKET_SIZE: usize = 20; // AH is 20 bytes, ICV = 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            6, 3, // next_hdr, payload_len = 3 (total AH 20 bytes)
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
            // ICV (8 bytes)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];

        let auth_hdr = unsafe { &*(packet_data.as_ptr() as *const AhHdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { auth_hdr.icv_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1));
        let expected_u64 = u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(output_slice[0], expected_u64);
    }

    #[test]
    fn test_extract_icv_multiple_chunks_exact_ah_and_packet_length() {
        const PACKET_SIZE: usize = 28; // AH is 28 bytes, ICV = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            6, 5, // next_hdr, payload_len = 5 (total AH 28 bytes)
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
            // ICV Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // ICV Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let auth_hdr = unsafe { &*(packet_data.as_ptr() as *const AhHdr) };
        let mut output_slice = [0u64; 2];

        let result = unsafe { auth_hdr.icv_buffer(&mut output_slice) };
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
    fn test_extract_icv_output_slice_is_too_small() {
        const PACKET_SIZE: usize = 28; // AH has 16 bytes of ICV (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            6, 5, // next_hdr, payload_len = 5 (total AH 28 bytes)
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
            // ICV Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // ICV Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let auth_hdr = unsafe { &*(packet_data.as_ptr() as *const AhHdr) };
        let mut output_slice = [0u64; 1]; // Only space for one u64.

        let result = unsafe { auth_hdr.icv_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1));
        assert_eq!(
            output_slice[0],
            u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])
        );
    }

    #[test]
    fn test_extract_icv_unexpected_end_of_packet() {
        // Create a packet with payload_len = 5 (total AH 28 bytes) but actual size is only 20 bytes
        // This will cause an UnexpectedEndOfPacket error when trying to read the second chunk
        const PACKET_SIZE: usize = 20; // Only enough data for AH header + 1 chunk
        let packet_data: [u8; PACKET_SIZE] = [
            6, 4, // next_hdr, payload_len = 4 (total AH 28 bytes, but we only have 20)
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
            // ICV Chunk 1 (only one chunk available)
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Missing second chunk that would be needed based on payload_len
        ];

        let auth_hdr = unsafe { &*(packet_data.as_ptr() as *const AhHdr) };
        let mut output_slice = [0u64; 2]; // Space for two u64s

        let result = unsafe { auth_hdr.icv_buffer(&mut output_slice) };

        // Expect UnexpectedEndOfPacket error with bytes_read=8 (one chunk) and count=1
        match result {
            Err(ChunkReaderError::UnexpectedEndOfPacket { bytes_read, count }) => {
                assert_eq!(bytes_read, 8); // 8 bytes (one chunk) were read
                assert_eq!(count, 1); // Trying to read the second chunk (index 1)
            }
            _ => panic!("Expected UnexpectedEndOfPacket error, got {:?}", result),
        }
    }
}
