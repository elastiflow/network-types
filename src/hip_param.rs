/// HIP (Host Identity Protocol) packets carry various information within their `HIP Parameters` section. 
/// These parameters follow a TLV (Type-Length-Value) structure, ensuring flexibility and extensibility. 
/// All encoded TLV parameters, including their Type, Length, Contents, and any necessary padding, 
/// are designed to have a total length that is a multiple of 8 bytes for proper alignment.
///
/// # HIP Parameter TLV Structure
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Type                |C|         Length              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                           Contents                            /
/// /                               +-+-+-+-+-+-+-+-+
/// |                               |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// ## Fields
///
/// * **Type (16 bits)**: A 16-bit field identifying the parameter. The most significant bit of this field is the **C-bit**.
///
/// * **C-bit (Critical) (1 bit)**: This bit is part of the `Type` field.
///     * If `1`, the parameter is **critical** and **MUST** be recognized by the recipient. 
///     * If `0`, the parameter is non-critical. Unrecognized non-critical parameters **SHOULD** be ignored by the recipient.
///     Consequently, critical parameters always have an odd `Type` value, while non-critical ones have an even `Type` value.
///
/// * **Length (15 bits)**: The length of the `Contents` field in bytes, **excluding** the `Type`, `C-bit`, `Length` fields, and any `Padding`.
///
/// * **Contents (variable length)**: The parameter-specific data, whose format and meaning are defined by the `Type` field.
///
/// * **Padding (0-7 bytes)**: Zero to seven bytes of padding added to the end of the parameter to ensure 
/// that the **total length** of the parameter (including `Type`, `C-bit`, `Length`, `Contents`, and `Padding`) is a multiple of 8 bytes. 
///
/// ## Total Length Calculation
///
/// The total length of a TLV parameter (in bytes) can be calculated from its `Length` field using the following formula:
///
/// $$ \text{Total Length} = 11 + \text{Length} - (\text{Length} + 3) \pmod{8} $$
///
/// This formula accounts for the 4 bytes of the `Type`/`C-bit`/`Length` fields, the `Contents` length, and enough padding to reach the next multiple of 8.

use crate::chunk_reader;
use core::{mem};

/// HIP Parameter TLV (Type-Length-Value) structure
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct HipParamTlv {
    /// Type field (15 bits) and Critical bit (1 bit)
    pub type_: [u8; 2],
    /// Length field (16 bits)
    pub len: [u8; 2],
}

impl HipParamTlv {
    /// The total size in bytes of the fixed part of the HIP Parameter TLV
    pub const LEN: usize = mem::size_of::<HipParamTlv>();

    /// Gets the Type value (15 bits).
    #[inline]
    pub fn param_type(&self) -> u16 {
        // Convert the 2 bytes to a u16 and mask out the critical bit
        let value = u16::from_be_bytes(self.type_);
        value & 0x7FFF // Mask out the most significant bit (critical bit)
    }

    /// Sets the Type value (15 bits).
    #[inline]
    pub fn set_param_type(&mut self, val: u16) {
        // Ensure we only use the lower 15 bits of val
        let masked_val = val & 0x7FFF;

        // Get the current value as a u16
        let current = u16::from_be_bytes(self.type_);

        // Preserve the critical bit and set the type
        let new_value = (current & 0x8000) | masked_val;

        // Store the result back
        self.type_ = new_value.to_be_bytes();
    }

    /// Gets the Critical bit.
    #[inline]
    pub fn critical(&self) -> bool {
        // Check if the most significant bit is set
        let value = u16::from_be_bytes(self.type_);
        (value & 0x8000) != 0
    }

    /// Sets the Critical bit.
    #[inline]
    pub fn set_critical(&mut self, val: bool) {
        // Get the current value as a u16
        let current = u16::from_be_bytes(self.type_);

        // Set or clear the critical bit while preserving the type
        let new_value = if val {
            current | 0x8000 // Set the most significant bit
        } else {
            current & 0x7FFF // Clear the most significant bit
        };

        // Store the result back
        self.type_ = new_value.to_be_bytes();
    }

    /// Gets the Length value.
    #[inline]
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(self.len)
    }

    /// Sets the Length value.
    #[inline]
    pub fn set_len(&mut self, len: u16) {
        self.len = len.to_be_bytes();
    }

    /// Calculates the total length of the HIP Parameter in bytes.
    /// The total length includes the fixed header (4 bytes), the contents, and padding.
    #[inline]
    pub fn total_param_len(&self) -> usize {
        let content_len = self.len() as usize;
        let padding = (8 - ((content_len + 4) % 8)) % 8;
        4 + content_len + padding
    }

    /// Calculates the content length of the HIP Parameter in bytes.
    #[inline]
    pub fn content_len(&self) -> usize {
        self.len() as usize
    }

    /// Constant for the size of each chunk when reading Contents data
    const CONTENTS_CHUNK_LEN: usize = mem::size_of::<u64>();

    /// Extracts the variable-length Contents from a HIP Parameter TLV
    /// into a caller-provided slice of `u64`.
    ///
    /// The HIP Parameter's `len` field determines the total length of
    /// the Contents section. This function reads the Contents data in 8-byte (u64) chunks.
    ///
    /// # Safety
    /// This method is unsafe because it performs raw pointer arithmetic and memory access.
    /// The caller must ensure:
    /// - The HipParamTlv instance points to valid memory containing a complete HIP Parameter
    /// - The memory region from the HipParamTlv through the end of the Contents is valid and accessible
    ///
    /// # Arguments
    /// - `contents_buffer`: A mutable slice of `u64` where the parsed Contents will be
    ///   written. Data is read from the packet (assumed to be in network byte order)
    ///   and converted to `u64` values in host byte order.
    ///
    /// # Returns
    /// A Result containing:
    /// - Ok(usize): The number of complete u64 words successfully read from the Contents and written
    ///   to `contents_buffer`. This may be:
    ///   - 0 if no Contents data is present
    ///   - Less than the total available Contents data if `contents_buffer` is too small to hold all Contents words
    /// - Err(ChunkReaderError): If an error occurred during reading:
    ///   - UnexpectedEndOfPacket: If the packet data ends unexpectedly before a complete chunk
    ///   - InvalidChunkLength: If CONTENTS_CHUNK_LEN is not equal to the size of u64
    pub unsafe fn contents_buffer(&self, contents_buffer: &mut [u64]) -> Result<usize, chunk_reader::ChunkReaderError> {
        let self_ptr: *const HipParamTlv = self;
        let self_ptr_u8: *const u8 = self_ptr as *const u8;
        let content_len = self.total_param_len();
        let start_data_ptr = (self_ptr_u8).add(HipParamTlv::LEN);
        let end_data_ptr = (self_ptr_u8).add(content_len);

        if self.content_len() == 0 {
            return Ok(0);
        }

        chunk_reader::read_chunks(
            start_data_ptr,
            end_data_ptr,
            contents_buffer,
            Self::CONTENTS_CHUNK_LEN
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a mutable HipParamTlv reference from a mutable byte array
    unsafe fn get_mut_hipparamtlv_ref_from_array<const N: usize>(data: &mut [u8; N]) -> &mut HipParamTlv {
        assert!(N >= HipParamTlv::LEN, "Array too small to cast to HipParamTlv for testing");
        &mut *(data.as_mut_ptr() as *mut HipParamTlv)
    }

    #[test]
    fn test_hipparamtlv_getters_and_setters() {
        const BUF_SIZE: usize = HipParamTlv::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let hip_param = unsafe { get_mut_hipparamtlv_ref_from_array(&mut packet_buf) };

        // Test param_type
        hip_param.set_param_type(0x1234);
        assert_eq!(hip_param.param_type(), 0x1234);

        // Test critical bit
        hip_param.set_critical(true);
        assert_eq!(hip_param.critical(), true);
        hip_param.set_critical(false);
        assert_eq!(hip_param.critical(), false);

        // Test length
        hip_param.set_len(0x5678);
        assert_eq!(hip_param.len(), 0x5678);
    }

    #[test]
    fn test_hipparamtlv_length_calculation_methods() {
        const BUF_SIZE: usize = HipParamTlv::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let hip_param = unsafe { get_mut_hipparamtlv_ref_from_array(&mut packet_buf) };

        // Test with length = 0
        hip_param.set_len(0);
        assert_eq!(hip_param.content_len(), 0);
        assert_eq!(hip_param.total_param_len(), 8); // 4 (header) + 0 (content) + 4 (padding) = 8

        // Test with length = 4
        hip_param.set_len(4);
        assert_eq!(hip_param.content_len(), 4);
        assert_eq!(hip_param.total_param_len(), 8); // 4 (header) + 4 (content) = 8, no padding needed

        // Test with length = 5
        hip_param.set_len(5);
        assert_eq!(hip_param.content_len(), 5);
        assert_eq!(hip_param.total_param_len(), 16); // 4 (header) + 5 (content) + 7 (padding) = 16
    }

    #[test]
    fn test_contents_buffer_when_content_len_is_zero() {
        // When content_len is 0, total_param_len is 8 (4 header + 4 padding)
        const PACKET_SIZE: usize = 8; // 4 bytes header + 4 bytes padding
        let packet_data: [u8; PACKET_SIZE] = [
            0x12, 0x34, // type_ (param_type = 0x1234, critical = false)
            0x00, 0x00, // len = 0
            0x00, 0x00, 0x00, 0x00, // padding
        ];

        let hip_param = unsafe { &*(packet_data.as_ptr() as *const HipParamTlv) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            hip_param.contents_buffer(&mut output_slice)
        };
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_contents_buffer_one_chunk_exact_param_and_packet_length() {
        // When content_len is 8, total_param_len is 16 (4 header + 8 content + 4 padding)
        const PACKET_SIZE: usize = 16; // Parameter is 16 bytes, Content = 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            0x12, 0x34, // type_ (param_type = 0x1234, critical = false)
            0x00, 0x08, // len = 8
            // Content (8 bytes)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            // Padding (4 bytes)
            0x00, 0x00, 0x00, 0x00,
        ];

        let hip_param = unsafe { &*(packet_data.as_ptr() as *const HipParamTlv) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            hip_param.contents_buffer(&mut output_slice)
        };
        assert_eq!(result, Ok(1));
        let expected_u64 = u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(output_slice[0], expected_u64);
    }

    #[test]
    fn test_contents_buffer_multiple_chunks_exact_param_and_packet_length() {
        // When content_len is 16, total_param_len is 24 (4 header + 16 content + 4 padding)
        const PACKET_SIZE: usize = 24; // Parameter is 24 bytes, Content = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            0x12, 0x34, // type_ (param_type = 0x1234, critical = false)
            0x00, 0x10, // len = 16
            // Content Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Content Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            // Padding (4 bytes)
            0x00, 0x00, 0x00, 0x00,
        ];

        let hip_param = unsafe { &*(packet_data.as_ptr() as *const HipParamTlv) };
        let mut output_slice = [0u64; 2];

        let result = unsafe {
            hip_param.contents_buffer(&mut output_slice)
        };
        assert_eq!(result, Ok(2));
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]));
        assert_eq!(output_slice[1], u64::from_be_bytes([0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00]));
    }

    #[test]
    fn test_contents_buffer_output_slice_is_too_small() {
        // When content_len is 16, total_param_len is 24 (4 header + 16 content + 4 padding)
        const PACKET_SIZE: usize = 24; // Parameter is 24 bytes, Content = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            0x12, 0x34, // type_ (param_type = 0x1234, critical = false)
            0x00, 0x10, // len = 16
            // Content Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Content Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            // Padding (4 bytes)
            0x00, 0x00, 0x00, 0x00,
        ];

        let hip_param = unsafe { &*(packet_data.as_ptr() as *const HipParamTlv) };
        let mut output_slice = [0u64; 1]; // Only room for 1 chunk, but there are 2

        let result = unsafe {
            hip_param.contents_buffer(&mut output_slice)
        };
        assert_eq!(result, Ok(1)); // Should only parse 1 chunk
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]));
    }

    #[test]
    fn test_contents_buffer_with_non_multiple_of_8_content_length() {
        const PACKET_SIZE: usize = 16; // Parameter is 16 bytes, Content = 10 bytes + 2 padding
        let packet_data: [u8; PACKET_SIZE] = [
            0x12, 0x34, // type_ (param_type = 0x1234, critical = false)
            0x00, 0x0A, // len = 10
            // Content (10 bytes)
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44,
            // Padding (2 bytes)
            0x00, 0x00,
        ];

        let hip_param = unsafe { &*(packet_data.as_ptr() as *const HipParamTlv) };
        let mut output_slice = [0u64; 2];

        let result = unsafe {
            hip_param.contents_buffer(&mut output_slice)
        };
        assert_eq!(result, Err(chunk_reader::ChunkReaderError::UnexpectedEndOfPacket { bytes_read: 8, count: 1 })); // Should only parse 1 complete chunk (8 bytes)
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]));
    }

    #[test]
    fn test_contents_buffer_unexpected_end_of_packet() {
        // Create a packet with len = 16 (total param 24 bytes) but actual size is only 12 bytes
        // This will cause an UnexpectedEndOfPacket error when trying to read the second chunk
        const PACKET_SIZE: usize = 12; // Only enough data for header + 1 chunk
        let packet_data: [u8; PACKET_SIZE] = [
            0x12, 0x34, // type_ (param_type = 0x1234, critical = false)
            0x00, 0xC, // len = 12 (total param 24 bytes, but we only have 12)
            // Content Chunk 1 (only one chunk available)
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // Content Chunk 2 is missing but would be needed based on len
            // Padding is also missing
        ];

        let hip_param = unsafe { &*(packet_data.as_ptr() as *const HipParamTlv) };
        let mut output_slice = [0u64; 2]; // Space for two u64s

        let result = unsafe {
            hip_param.contents_buffer(&mut output_slice)
        };

        // Expect UnexpectedEndOfPacket error with bytes_read=8 (one chunk) and count=1
        match result {
            Err(chunk_reader::ChunkReaderError::UnexpectedEndOfPacket { bytes_read, count }) => {
                assert_eq!(bytes_read, 8); // 8 bytes (one chunk) were read
                assert_eq!(count, 1); // Trying to read the second chunk (index 1)
            }
            _ => panic!("Expected UnexpectedEndOfPacket error, got {:?}", result),
        }
    }
}
