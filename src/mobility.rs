use crate::chunk_reader;
/// # Mobility Header Format Section 6.1.1 - https://datatracker.ietf.org/doc/html/rfc3775
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Payload Proto |  Header Len   |   MH Type     |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                                                               |
/// .                                                               .
/// .                       Message Data                            .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// ## Fields
///
/// * **Payload Proto (8 bits)**: An 8-bit selector identifying the type of header immediately following the Mobility Header. 
///
/// * **Header Len (8 bits)**: An 8-bit unsigned integer representing the length of the Mobility Header in units of 8 octets, **excluding the first 8 octets**. 
///
/// * **MH Type (8 bits)**: An 8-bit selector that identifies the specific mobility message. 
///
/// * **Reserved (8 bits)**: Reserved for future use. Should be 0 
///
/// * **Checksum (16 bits)**: A 16-bit unsigned integer containing the checksum of the Mobility Header. 
///
/// * **Message Data (variable length)**: A variable-length field containing data specific to the `MH Type` indicated.

/// Mobility Header
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MobilityHdr {
    pub payload_proto: u8,
    pub header_len: u8,
    pub mh_type: u8,
    pub reserved: u8,
    pub checksum: [u8; 2],
    pub msg_data_start: [u8; 2], // Captures last two bytes of standard mobility header length
}

const MESSAGE_DATA_CHUNK_LEN: usize = core::mem::size_of::<u64>();

/// Errors that can occur during Mobility Header parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum MobilityHdrError {
    /// Packet data ended unexpectedly, or a declared length exceeds packet boundaries.
    OutOfBounds,
    /// The Mobility Header indicates a length that extends beyond the provided packet data.
    UnexpectedEndOfPacket,
}

impl MobilityHdr {
    /// The total size in bytes of the fixed part of the Mobility Header
    pub const LEN: usize = 8; // Fixed size of the Mobility Header (first 8 bytes)

    /// Gets the Payload Proto value.
    pub fn payload_proto(&self) -> u8 {
        self.payload_proto
    }

    /// Sets the Payload Proto value.
    pub fn set_payload_proto(&mut self, payload_proto: u8) {
        self.payload_proto = payload_proto;
    }

    /// Gets the Header Len value.
    /// This value is the length of the Mobility Header in units of 8 octets, excluding the first 8 octets.
    pub fn header_len(&self) -> u8 {
        self.header_len
    }

    /// Sets the Header Len value.
    pub fn set_header_len(&mut self, header_len: u8) {
        self.header_len = header_len;
    }

    /// Gets the MH Type value.
    pub fn mh_type(&self) -> u8 {
        self.mh_type
    }

    /// Sets the MH Type value.
    pub fn set_mh_type(&mut self, mh_type: u8) {
        self.mh_type = mh_type;
    }

    /// Gets the Reserved field.
    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    /// Sets the Reserved field.
    pub fn set_reserved(&mut self, reserved: u8) {
        self.reserved = reserved;
    }

    /// Gets the Checksum as a 16-bit value.
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the Checksum from a 16-bit value.
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Gets the Message Data Start as a 16-bit value.
    pub fn msg_data_start(&self) -> u16 {
        u16::from_be_bytes(self.msg_data_start)
    }

    /// Sets the Message Data Start from a 16-bit value.
    pub fn set_msg_data_start(&mut self, msg_data_start: u16) {
        self.msg_data_start = msg_data_start.to_be_bytes();
    }

    /// Calculates the total length of the Mobility Header in bytes.
    /// The Header Len is in 8-octet units, excluding the first 8 octets.
    /// So, total length = 8 + (header_len * 8).
    pub fn total_hdr_len(&self) -> usize {
        8 + (self.header_len as usize * 8)
    }

    /// Calculates the length of the Message Data in bytes.
    /// Message Data length = Total Header Length - Fixed Header Length.
    pub fn message_data_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(MobilityHdr::LEN)
    }

    /// Extracts the variable-length Message Data from the Mobility Header
    /// into a caller-provided slice of `u64`.
    ///
    /// The Mobility Header's `header_len` field determines the total length of
    /// the Mobility header, from which the length of the Message Data is derived. The Message Data is the
    /// data that follows the fixed part of the Mobility Header. This function
    /// reads the Message Data in 8-byte (u64) chunks.
    ///
    /// # Safety
    /// This method is unsafe because it performs raw pointer arithmetic and memory access.
    /// The caller must ensure:
    /// - The MobilityHdr instance points to valid memory containing a complete Mobility Header
    /// - The memory region from the MobilityHdr through the end of the Message Data is valid and accessible
    /// - The total length calculated from header_len does not exceed available memory bounds
    ///
    /// # Arguments
    /// - `message_data_buffer`: A mutable slice of `u64` where the parsed Message Data will be
    ///   written. Data is read from the packet (assumed to be in network byte order)
    ///   and converted to `u64` values in host byte order.
    ///
    /// # Returns
    /// A Result containing:
    /// - Ok(usize): The number of complete u64 words successfully read from the Message Data and written
    ///   to `message_data_buffer`. This may be:
    ///   - 0 if no Message Data is present (`total_hdr_len` <= `MobilityHdr::LEN`)
    ///   - Less than the total available Message Data if:
    ///     - `message_data_buffer` is too small to hold all Message Data words
    ///     - The remaining Message Data bytes are not enough for a complete u64 word
    /// - Err(ChunkReaderError): If an error occurred during reading, such as:
    ///   - UnexpectedEndOfPacket: If the packet data ends unexpectedly
    ///   - InvalidChunkLength: If the chunk length is not equal to the size of u64
    pub unsafe fn message_data_buffer(&self, message_data_buffer: &mut [u64]) -> Result<usize, chunk_reader::ChunkReaderError> {
        let self_ptr: *const MobilityHdr = self;
        let self_ptr_u8: *const u8 = self_ptr as *const u8;
        let total_hdr_len = self.total_hdr_len();
        let start_data_ptr = (self_ptr_u8).add(MobilityHdr::LEN);
        let end_data_ptr = (self_ptr_u8).add(total_hdr_len);

        if total_hdr_len <= MobilityHdr::LEN {
            return Ok(0);
        }

        chunk_reader::read_chunks(start_data_ptr, end_data_ptr, message_data_buffer, MESSAGE_DATA_CHUNK_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a mutable MobilityHdr reference from a mutable byte array.
    unsafe fn get_mut_mobilityhdr_ref_from_array<const N: usize>(data: &mut [u8; N]) -> &mut MobilityHdr {
        assert!(N >= MobilityHdr::LEN, "Array too small to cast to MobilityHdr for testing");
        &mut *(data.as_mut_ptr() as *mut MobilityHdr)
    }

    #[test]
    fn test_mobilityhdr_getters_and_setters() {
        const BUF_SIZE: usize = MobilityHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let mobility_hdr = unsafe { get_mut_mobilityhdr_ref_from_array(&mut packet_buf) };

        // Test payload_proto
        mobility_hdr.set_payload_proto(6); // Example: TCP
        assert_eq!(mobility_hdr.payload_proto(), 6);
        assert_eq!(mobility_hdr.payload_proto, 6);

        // Test header_len
        mobility_hdr.set_header_len(2); // Example: 2 * 8 = 16 bytes of additional data
        assert_eq!(mobility_hdr.header_len(), 2);
        assert_eq!(mobility_hdr.header_len, 2);

        // Test mh_type
        mobility_hdr.set_mh_type(5);
        assert_eq!(mobility_hdr.mh_type(), 5);
        assert_eq!(mobility_hdr.mh_type, 5);

        // Test reserved
        mobility_hdr.set_reserved(0);
        assert_eq!(mobility_hdr.reserved(), 0);
        assert_eq!(mobility_hdr.reserved, 0);

        // Test checksum
        mobility_hdr.set_checksum(0x1234);
        assert_eq!(mobility_hdr.checksum(), 0x1234);
        assert_eq!(mobility_hdr.checksum, [0x12, 0x34]);

        // Test msg_data_start
        mobility_hdr.set_msg_data_start(0x5678);
        assert_eq!(mobility_hdr.msg_data_start(), 0x5678);
        assert_eq!(mobility_hdr.msg_data_start, [0x56, 0x78]);
    }

    #[test]
    fn test_mobilityhdr_length_calculation_methods() {
        const BUF_SIZE: usize = MobilityHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let mobility_hdr = unsafe { get_mut_mobilityhdr_ref_from_array(&mut packet_buf) };

        // Test with header_len = 0
        mobility_hdr.set_header_len(0);
        assert_eq!(mobility_hdr.total_hdr_len(), 8);
        assert_eq!(mobility_hdr.message_data_len(), 0);

        // Test with header_len = 1
        mobility_hdr.set_header_len(1);
        assert_eq!(mobility_hdr.total_hdr_len(), 16);
        assert_eq!(mobility_hdr.message_data_len(), 8);

        // Test with header_len = 3
        mobility_hdr.set_header_len(3);
        assert_eq!(mobility_hdr.total_hdr_len(), 32);
        assert_eq!(mobility_hdr.message_data_len(), 24);

        // Test with header_len = 255 (max value)
        mobility_hdr.set_header_len(255);
        assert_eq!(mobility_hdr.total_hdr_len(), 8 + (255 * 8));
        assert_eq!(mobility_hdr.message_data_len(), 8 + (255 * 8) - MobilityHdr::LEN);
    }

    #[test]
    fn test_message_data_buffer_when_header_len_is_zero() {
        const PACKET_SIZE: usize = MobilityHdr::LEN; // 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            6, 0, // payload_proto, header_len = 0
            5, 0, // mh_type, reserved
            0x12, 0x34, // checksum
            0x56, 0x78, // msg_data_start
        ];

        let mobility_hdr = unsafe { &*(packet_data.as_ptr() as *const MobilityHdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { mobility_hdr.message_data_buffer(&mut output_slice) };
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_message_data_buffer_one_chunk_exact_mobility_and_packet_length() {
        const PACKET_SIZE: usize = 16; // Mobility Header is 16 bytes, Message Data = 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            6, 1, // payload_proto, header_len = 1 (total 16 bytes)
            5, 0, // mh_type, reserved
            0x12, 0x34, // checksum
            0x56, 0x78, // msg_data_start
            // Message Data (8 bytes)
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        ];

        let mobility_hdr = unsafe { &*(packet_data.as_ptr() as *const MobilityHdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { mobility_hdr.message_data_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1));
        let expected_u64 = u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
        assert_eq!(output_slice[0], expected_u64);
    }

    #[test]
    fn test_message_data_buffer_multiple_chunks_exact_mobility_and_packet_length() {
        const PACKET_SIZE: usize = 24; // Mobility Header is 24 bytes, Message Data = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            6, 2, // payload_proto, header_len = 2 (total 24 bytes)
            5, 0, // mh_type, reserved
            0x12, 0x34, // checksum
            0x56, 0x78, // msg_data_start
            // Message Data Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Message Data Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let mobility_hdr = unsafe { &*(packet_data.as_ptr() as *const MobilityHdr) };
        let mut output_slice = [0u64; 2];

        let result = unsafe { mobility_hdr.message_data_buffer(&mut output_slice) };
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
    fn test_message_data_buffer_output_slice_is_too_small() {
        const PACKET_SIZE: usize = 24; // Mobility Header has 16 bytes of Message Data (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            6, 2, // payload_proto, header_len = 2 (total 24 bytes)
            5, 0, // mh_type, reserved
            0x12, 0x34, // checksum
            0x56, 0x78, // msg_data_start
            // Message Data Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Message Data Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let mobility_hdr = unsafe { &*(packet_data.as_ptr() as *const MobilityHdr) };
        let mut output_slice = [0u64; 1]; // Only space for one u64.

        let result = unsafe { mobility_hdr.message_data_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1));
        assert_eq!(
            output_slice[0],
            u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])
        );
    }

    #[test]
    fn test_message_data_buffer_with_incomplete_chunk() {
        const PACKET_SIZE: usize = 20; // Mobility Header is 20 bytes, Message Data = 12 bytes (1 complete chunk + 4 bytes)
        let packet_data: [u8; PACKET_SIZE] = [
            6, 1, // payload_proto, header_len = 1 (total 16 bytes)
            5, 0, // mh_type, reserved
            0x12, 0x34, // checksum
            0x56, 0x78, // msg_data_start
            // Message Data (12 bytes)
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // Complete chunk
            0x33, 0x44, 0x55, 0x66, // Incomplete chunk (only 4 bytes)
        ];

        let mobility_hdr = unsafe { &*(packet_data.as_ptr() as *const MobilityHdr) };
        let mut output_slice = [0u64; 2]; // Space for two u64s.

        let result = unsafe { mobility_hdr.message_data_buffer(&mut output_slice) };
        assert_eq!(result, Ok(1)); // Only one complete chunk should be read
        assert_eq!(
            output_slice[0],
            u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])
        );
    }

    #[test]
    fn test_message_data_buffer_corrupt_header_len() {
        const PACKET_SIZE: usize = 12; // Mobility Header should be 16 bytes but we only provide 12
        let packet_data: [u8; PACKET_SIZE] = [
            6, 0, // payload_proto, header_len = 11 (total 12 bytes)
            5, 0, // mh_type, reserved
            0x12, 0x34, // checksum
            0x56, 0x78, // msg_data_start
            // Only 4 bytes of the expected 8 bytes of Message Data
            0x11, 0x22, 0x33, 0x44,
        ];

        let mobility_hdr = unsafe { &*(packet_data.as_ptr() as *const MobilityHdr) };
        let mut output_slice = [0u64; 1];

        let result = unsafe { mobility_hdr.message_data_buffer(&mut output_slice) };
        assert_eq!(result, Ok(0));
    }
}
