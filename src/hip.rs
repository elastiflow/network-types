/// The Host Identity Protocol (HIP) version 2 is designed to separate the identifier and locator roles of IP addresses, enabling secure and flexible host mobility and multi-homing. All HIP packets begin with a fixed header structure.
///
/// The HIP header is logically an IPv6 extension header. However, for HIPv2, the `Next Header` field in the immediately preceding IPv6 header is typically set to 59 (`IPPROTO_NONE`), indicating no further headers directly follow the HIP header. Implementations should ignore trailing data if an unimplemented `Next Header` value is received.
///
/// # Host Identity Protocol (HIP) Version 2 Fixed Header Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |           Controls            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |             Sender's Host Identity Tag (HIT)                  |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |           Receiver's Host Identity Tag (HIT)                  |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                          HIP Parameters                         /
/// /                                                               /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// ## Fields
///
/// * **Next Header (8 bits)**: In the context of an IPv6 extension header, this field would normally indicate the type of the next header. 
/// For HIPv2, this document primarily defines behavior for a value of 59 (`IPPROTO_NONE`). Future specifications *MAY* define other values.
///
/// * **Header Length (8 bits)**: Contains the combined length of the HIP Header and any encapsulated HIP parameters, measured in 8-byte units, 
/// and **excluding the first 8 bytes** (i.e., excluding the `Next Header` to `Controls` fields). 
/// Since the sender's and receiver's HITs are always present (32 bytes), the minimum value for this field is 4. 
/// The maximum length of the `HIP Parameters` field is limited by this field to 2008 bytes.
///
/// * **Fixed Bit (1 bit)**: This bit (position 16) **MUST** be 0 when sent and **MUST** be ignored when received, 
/// for implementations adhering solely to this specification. This is for SHIM6 compatibility.
///
/// * **Packet Type (7 bits)**: Indicates the specific type of HIP packet. 
/// If a HIP host receives a packet with an unrecognized `Packet Type`, it **MUST** drop the packet.
///
/// * **Version (4 bits)**: The HIP protocol version. For this specification, the version is 2. 
/// The version number is incremented only for incompatible protocol changes.
///
/// * **Reserved (3 bits)**: Reserved for future use. 
/// These bits **MUST** be zero when sent and **MUST** be ignored when handling a received packet.
///
/// * **Fixed Bit (1 bit)**: This bit (position 31) **MUST** be 1 when sent and **MUST** be ignored when received, 
/// for implementations adhering solely to this specification. This is for SHIM6 compatibility.
///
/// * **Checksum (16 bits)**: A checksum covering the HIP header, HIP parameters, and crucially, 
/// the source and destination IP addresses from the IP header. Due to its dependency on IP addresses, 
/// this checksum **MUST** be recomputed by HIP-aware NAT devices.
///
/// * **Controls (16 bits)**: This field contains various flags and control bits that govern the processing of the HIP packet.
///
/// * **Sender's Host Identity Tag (HIT) (16 bytes)**: The Host Identity Tag of the sender of the HIP packet. 
///
/// * **Receiver's Host Identity Tag (HIT) (16 bytes)**: The Host Identity Tag of the intended receiver of the HIP packet. 
///
/// * **HIP Parameters (variable length)**: A variable-length field containing various HIP parameters that provide additional information or data specific to the `Packet Type`.

use core::mem;
use crate::chunk_reader;
use crate::hip_param::{HipParamTlv};

/// HIP version 2 protocol header structure
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct HipHdr {
    /// Next Header field (8 bits)
    pub next_hdr: u8,
    /// Header Length field (8 bits)
    pub hdr_len: u8,
    /// Fixed bit (1 bit) + Packet Type (7 bits)
    pub packet_type_field: u8,
    /// Version (4 bits) + Reserved (3 bits) + Fixed bit (1 bit)
    pub version_field: u8,
    /// Checksum field (16 bits)
    pub checksum: [u8; 2],
    /// Controls field (16 bits)
    pub controls: [u8; 2],
    /// Sender's Host Identity Tag (HIT) (16 bytes)
    pub sender_hit: [u8; 16],
    /// Receiver's Host Identity Tag (HIT) (16 bytes)
    pub receiver_hit: [u8; 16],
}

impl HipHdr {
    /// The total size in bytes of the fixed part of the HIP header
    pub const LEN: usize = mem::size_of::<HipHdr>();

    /// The fixed size of the HIP header including the two HITs
    pub const FIXED_HEADER_SIZE: usize = 40; // 8 bytes fixed header + 32 bytes HITs

    /// Gets the Next Header value.
    #[inline]
    pub fn next_hdr(&self) -> u8 {
        self.next_hdr
    }

    /// Sets the Next Header value.
    #[inline]
    pub fn set_next_hdr(&mut self, val: u8) {
        self.next_hdr = val;
    }

    /// Gets the Header Length value.
    #[inline]
    pub fn hdr_len(&self) -> u8 {
        self.hdr_len
    }

    /// Sets the Header Length value.
    #[inline]
    pub fn set_hdr_len(&mut self, val: u8) {
        self.hdr_len = val;
    }

    /// Gets the Packet Type value (7 bits).
    #[inline]
    pub fn packet_type(&self) -> u8 {
        self.packet_type_field & 0x7F
    }

    /// Sets the Packet Type value (7 bits).
    #[inline]
    pub fn set_packet_type(&mut self, val: u8) {
        // Preserve the fixed bit (bit 7) and set the packet type (bits 0-6)
        self.packet_type_field = (self.packet_type_field & 0x80) | (val & 0x7F);
    }

    /// Gets the first fixed bit (bit 7 of packet_type_field).
    #[inline]
    pub fn fixed_bit1(&self) -> bool {
        (self.packet_type_field & 0x80) != 0
    }

    /// Sets the first fixed bit (bit 7 of packet_type_field).
    #[inline]
    pub fn set_fixed_bit1(&mut self, val: bool) {
        if val {
            self.packet_type_field |= 0x80;
        } else {
            self.packet_type_field &= 0x7F;
        }
    }

    /// Gets the Version value (4 bits).
    #[inline]
    pub fn version(&self) -> u8 {
        (self.version_field >> 4) & 0x0F
    }

    /// Sets the Version value (4 bits).
    #[inline]
    pub fn set_version(&mut self, val: u8) {
        // Preserve the reserved bits and fixed bit, set the version (bits 4-7)
        self.version_field = (self.version_field & 0x0F) | ((val & 0x0F) << 4);
    }

    /// Gets the Reserved bits (3 bits).
    #[inline]
    pub fn reserved(&self) -> u8 {
        (self.version_field >> 1) & 0x07
    }

    /// Sets the Reserved bits (3 bits).
    #[inline]
    pub fn set_reserved(&mut self, val: u8) {
        // Preserve the version and fixed bit, set the reserved bits (bits 1-3)
        self.version_field = (self.version_field & 0xF1) | ((val & 0x07) << 1);
    }

    /// Gets the second fixed bit (bit 0 of version_field).
    #[inline]
    pub fn fixed_bit2(&self) -> bool {
        (self.version_field & 0x01) != 0
    }

    /// Sets the second fixed bit (bit 0 of version_field).
    #[inline]
    pub fn set_fixed_bit2(&mut self, val: bool) {
        if val {
            self.version_field |= 0x01;
        } else {
            self.version_field &= 0xFE;
        }
    }

    /// Gets the Checksum value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the Checksum value.
    #[inline]
    pub fn set_checksum(&mut self, val: u16) {
        self.checksum = val.to_be_bytes();
    }

    /// Gets the Controls value.
    #[inline]
    pub fn controls(&self) -> u16 {
        u16::from_be_bytes(self.controls)
    }

    /// Sets the Controls value.
    #[inline]
    pub fn set_controls(&mut self, val: u16) {
        self.controls = val.to_be_bytes();
    }

    /// Calculates the total length of the HIP packet in bytes.
    #[inline]
    pub fn total_length(&self) -> usize {
        ((self.hdr_len as usize) + 1) << 3
    }

    /// Calculates the length of the HIP Parameters area in bytes.
    #[inline]
    pub fn params_length(&self) -> usize {
        self.total_length() - Self::FIXED_HEADER_SIZE
    }

    /// Parses the HIP Parameters from a HIP packet and stores their contents in a provided output slice.
    ///
    /// This function iterates through all HIP parameters in the packet and calls
    /// `contents_buffer` for each one, storing the results in the provided output slice.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences raw pointers and performs
    /// pointer arithmetic. The caller must ensure that:
    ///
    /// - `self` points to a valid `HipHdr` structure.
    /// - `packet_end_ptr` points to the end of the packet buffer.
    /// - `output_slice` is large enough to hold all the parsed parameter contents.
    ///
    /// # Arguments
    ///
    /// - `packet_end_ptr`: A pointer to the end of the packet buffer.
    /// - `output_slice`: A mutable slice to store the parsed parameter contents as u64 values.
    ///
    /// # Returns
    ///
    /// - `usize`: The number of u64 values successfully parsed and stored in `output_slice`.
    pub unsafe fn parse_params(
        &self,
        packet_end_ptr: *const u8,
        output_slice: &mut [u64],
    ) -> usize
    {
        let self_ptr: *const HipHdr = self;
        let params_length = self.params_length();

        // If there are no parameters, return early
        if params_length == 0 {
            return 0;
        }

        // Calculate the start and end of the parameters area
        let params_start_ptr = (self_ptr as *const u8).add(HipHdr::FIXED_HEADER_SIZE);
        let params_end_ptr = params_start_ptr.add(params_length);

        // Check if the parameters area is within bounds
        if params_end_ptr > packet_end_ptr {
            return 0;
        }

        let mut current_param_ptr = params_start_ptr;
        let mut total_u64_count = 0;

        // Iterate through the parameters
        while current_param_ptr < params_end_ptr {
            // Check if there's enough space for a parameter header
            if current_param_ptr.add(HipParamTlv::LEN) > params_end_ptr {
                break;
            }

            let param_tlv_ptr = current_param_ptr as *const HipParamTlv;
            let param_tlv = &*param_tlv_ptr;
            let param_total_len = param_tlv.total_param_len();

            // Check if the parameter fits within the parameters area
            if current_param_ptr.add(param_total_len) > params_end_ptr {
                return total_u64_count;
            }

            if total_u64_count >= output_slice.len() {
                break;
            }

            // Calculate parameter content start and end pointers
            let content_start_ptr = current_param_ptr.add(HipParamTlv::LEN);
            let content_len = param_tlv.content_len();
            let content_end_ptr = content_start_ptr.add(content_len);

            // Use read_chunks to parse the parameter contents
            let remaining_slice = &mut output_slice[total_u64_count..];
            let u64_count = match chunk_reader::read_chunks::<u64, 8>(
                content_start_ptr,
                content_end_ptr,
                remaining_slice,
                8, // chunk size for u64
            ) {
                Ok(count) => count,
                Err(chunk_reader::ChunkReaderError::UnexpectedEndOfPacket { bytes_read: _bytes_read, count }) => count,
                Err(chunk_reader::ChunkReaderError::InvalidChunkLength { expected: _expected, found: _found }) => 0,
            };

            // Update the total count of u64 values parsed
            total_u64_count += u64_count;

            // Move to the next parameter
            current_param_ptr = current_param_ptr.add(param_total_len);
        }

        total_u64_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a mutable HipHdr reference from a mutable byte array
    unsafe fn get_mut_hiphdr_ref_from_array<const N: usize>(data: &mut [u8; N]) -> &mut HipHdr {
        assert!(N >= HipHdr::LEN, "Array too small to cast to HipHdr for testing");
        &mut *(data.as_mut_ptr() as *mut HipHdr)
    }

    #[test]
    fn test_hiphdr_getters_and_setters() {
        const BUF_SIZE: usize = HipHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let hip_hdr = unsafe { get_mut_hiphdr_ref_from_array(&mut packet_buf) };

        // Test next_hdr
        hip_hdr.set_next_hdr(59);
        assert_eq!(hip_hdr.next_hdr(), 59);

        // Test hdr_len
        hip_hdr.set_hdr_len(4);
        assert_eq!(hip_hdr.hdr_len(), 4);

        // Test packet_type
        hip_hdr.set_packet_type(0x12);
        assert_eq!(hip_hdr.packet_type(), 0x12);

        // Test fixed_bit1
        hip_hdr.set_fixed_bit1(false);
        assert_eq!(hip_hdr.fixed_bit1(), false);
        hip_hdr.set_fixed_bit1(true);
        assert_eq!(hip_hdr.fixed_bit1(), true);

        // Test version
        hip_hdr.set_version(2);
        assert_eq!(hip_hdr.version(), 2);

        // Test reserved
        hip_hdr.set_reserved(0);
        assert_eq!(hip_hdr.reserved(), 0);

        // Test fixed_bit2
        hip_hdr.set_fixed_bit2(true);
        assert_eq!(hip_hdr.fixed_bit2(), true);

        // Test checksum
        hip_hdr.set_checksum(0x1234);
        assert_eq!(hip_hdr.checksum(), 0x1234);

        // Test controls
        hip_hdr.set_controls(0x5678);
        assert_eq!(hip_hdr.controls(), 0x5678);
    }

    #[test]
    fn test_hiphdr_length_calculation_methods() {
        const BUF_SIZE: usize = HipHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let hip_hdr = unsafe { get_mut_hiphdr_ref_from_array(&mut packet_buf) };

        // Test with hdr_len = 4 (minimum value)
        hip_hdr.set_hdr_len(4);
        assert_eq!(hip_hdr.total_length(), 40); // (4 + 1) * 8 = 40
        assert_eq!(hip_hdr.params_length(), 0); // 40 - 40 = 0

        // Test with hdr_len = 5
        hip_hdr.set_hdr_len(5);
        assert_eq!(hip_hdr.total_length(), 48); // (5 + 1) * 8 = 48
        assert_eq!(hip_hdr.params_length(), 8); // 48 - 40 = 8
    }

    #[test]
    fn test_parse_params() {
        // Create a test packet with a HIP header and two parameters
        // Each parameter: 4 bytes header + 8 bytes content = 12 bytes
        // With padding to 8-byte boundary: 16 bytes each
        // Total packet size: 40 (fixed header) + 16 (param1) + 16 (param2) = 72 bytes
        const PACKET_SIZE: usize = 72;
        let mut packet_data = [0u8; PACKET_SIZE];

        // Set up the HIP header
        let hip_hdr = unsafe { get_mut_hiphdr_ref_from_array(&mut packet_data) };
        hip_hdr.set_next_hdr(59);
        hip_hdr.set_hdr_len(8); // (72 - 8) / 8 = 8 (header length in 8-byte units minus 1)
        hip_hdr.set_packet_type(0x10);
        hip_hdr.set_version(2);
        hip_hdr.set_fixed_bit2(true);

        // Set up the first parameter at offset 40
        let param1_offset = HipHdr::FIXED_HEADER_SIZE;
        let param1_ptr = unsafe { packet_data.as_mut_ptr().add(param1_offset) as *mut HipParamTlv };
        unsafe {
            (*param1_ptr).type_ = [0x00, 0x01]; // Type 1
            (*param1_ptr).len = [0x00, 0x08]; // Length 8 bytes (content only)

            // Set content bytes (8 bytes) - this will form our first u64
            let content_ptr = packet_data.as_mut_ptr().add(param1_offset + HipParamTlv::LEN);
            for i in 0..8 {
                *content_ptr.add(i) = (i + 1) as u8; // [1, 2, 3, 4, 5, 6, 7, 8]
            }
            // Add padding to align to 8-byte boundary (4 bytes of padding)
            for i in 8..12 {
                *content_ptr.add(i) = 0;
            }
        }

        // Set up the second parameter at offset 56 (40 + 16)
        let param2_offset = param1_offset + 16; // 4 bytes header + 8 bytes content + 4 bytes padding
        let param2_ptr = unsafe { packet_data.as_mut_ptr().add(param2_offset) as *mut HipParamTlv };
        unsafe {
            (*param2_ptr).type_ = [0x00, 0x02]; // Type 2
            (*param2_ptr).len = [0x00, 0x08]; // Length 8 bytes (content only)

            // Set content bytes (8 bytes) - this will form our second u64
            let content_ptr = packet_data.as_mut_ptr().add(param2_offset + HipParamTlv::LEN);
            for i in 0..8 {
                *content_ptr.add(i) = (i + 9) as u8; // [9, 10, 11, 12, 13, 14, 15, 16]
            }
            // Add padding to align to 8-byte boundary (4 bytes of padding)
            for i in 8..12 {
                *content_ptr.add(i) = 0;
            }
        }

        // Create an output slice to store the parsed parameters
        let mut output_slice = [0u64; 4];

        // Call parse_params
        let hip_hdr_ref = unsafe { &*(packet_data.as_ptr() as *const HipHdr) };
        let result = unsafe {
            hip_hdr_ref.parse_params(
                packet_data.as_ptr().add(PACKET_SIZE),
                &mut output_slice,
            )
        };

        // Check the result
        assert_eq!(result, 2); // Should parse 2 u64 values

        // Check the parsed values
        let expected_value1 = u64::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let expected_value2 = u64::from_be_bytes([9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(output_slice[0], expected_value1);
        assert_eq!(output_slice[1], expected_value2);
    }

    #[test]
    fn test_parse_params_with_insufficient_output_space() {
        // Create a test packet with a HIP header and two parameters
        // Total packet size: 40 (fixed header) + 16 (param1) + 16 (param2) = 72 bytes
        const PACKET_SIZE: usize = 72;
        let mut packet_data = [0u8; PACKET_SIZE];

        // Set up the HIP header
        let hip_hdr = unsafe { get_mut_hiphdr_ref_from_array(&mut packet_data) };
        hip_hdr.set_next_hdr(59);
        hip_hdr.set_hdr_len(8); // (72 bytes total - 8 bytes header) / 8 = 8
        hip_hdr.set_packet_type(0x10);
        hip_hdr.set_version(2);
        hip_hdr.set_fixed_bit2(true);

        // Set up the first parameter at offset 40
        let param1_offset = HipHdr::FIXED_HEADER_SIZE;
        let param1_ptr = unsafe { packet_data.as_mut_ptr().add(param1_offset) as *mut HipParamTlv };
        unsafe {
            (*param1_ptr).type_ = [0x00, 0x01]; // Type 1
            (*param1_ptr).len = [0x00, 0x08]; // Length 8 bytes

            // Set content bytes (8 bytes)
            let content_ptr = packet_data.as_mut_ptr().add(param1_offset + HipParamTlv::LEN);
            for i in 0..8 {
                *content_ptr.add(i) = (i + 1) as u8;
            }
        }

        // Set up the second parameter at offset 56 (40 + 16)
        let param2_offset = param1_offset + 16;
        let param2_ptr = unsafe { packet_data.as_mut_ptr().add(param2_offset) as *mut HipParamTlv };
        unsafe {
            (*param2_ptr).type_ = [0x00, 0x02]; // Type 2
            (*param2_ptr).len = [0x00, 0x08]; // Length 8 bytes

            // Set content bytes (8 bytes)
            let content_ptr = packet_data.as_mut_ptr().add(param2_offset + HipParamTlv::LEN);
            for i in 0..8 {
                *content_ptr.add(i) = (i + 9) as u8;
            }
        }

        // Create an output slice with space for only one parameter
        let mut output_slice = [0u64; 1];

        // Call parse_params
        let hip_hdr_ref = unsafe { &*(packet_data.as_ptr() as *const HipHdr) };
        let result = unsafe {
            hip_hdr_ref.parse_params(
                packet_data.as_ptr().add(PACKET_SIZE),
                &mut output_slice,
            )
        };

        // Check the result
        assert_eq!(result, 1); // Should parse only 1 u64 value due to limited space

        // Check the parsed value
        let expected_value = u64::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(output_slice[0], expected_value);
    }

    #[test]
    fn test_parse_params_with_large_parameter() {
        // Create a test packet with a HIP header and one large parameter (16 bytes content)
        // Total packet size: 40 (fixed header) + 24 (param1) = 64 bytes
        const PACKET_SIZE: usize = 64;
        let mut packet_data = [0u8; PACKET_SIZE];

        // Set up the HIP header
        let hip_hdr = unsafe { get_mut_hiphdr_ref_from_array(&mut packet_data) };
        hip_hdr.set_next_hdr(59);
        hip_hdr.set_hdr_len(7); // (64 bytes total - 8 bytes header) / 8 = 7
        hip_hdr.set_packet_type(0x10);
        hip_hdr.set_version(2);
        hip_hdr.set_fixed_bit2(true);

        // Set up the parameter at offset 40
        let param_offset = HipHdr::FIXED_HEADER_SIZE;
        let param_ptr = unsafe { packet_data.as_mut_ptr().add(param_offset) as *mut HipParamTlv };
        unsafe {
            (*param_ptr).type_ = [0x00, 0x01]; // Type 1
            (*param_ptr).len = [0x00, 0x10]; // Length 16 bytes (2 u64s)

            // Set content bytes (16 bytes)
            let content_ptr = packet_data.as_mut_ptr().add(param_offset + HipParamTlv::LEN);
            for i in 0..16 {
                *content_ptr.add(i) = (i + 1) as u8;
            }
        }

        // Create an output slice to store the parsed parameters
        let mut output_slice = [0u64; 4];

        // Call parse_params
        let hip_hdr_ref = unsafe { &*(packet_data.as_ptr() as *const HipHdr) };
        let result = unsafe {
            hip_hdr_ref.parse_params(
                packet_data.as_ptr().add(PACKET_SIZE),
                &mut output_slice,
            )
        };

        // Check the result
        assert_eq!(result, 2); // Should parse 2 u64 values

        // Check the parsed values
        let expected_value1 = u64::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let expected_value2 = u64::from_be_bytes([9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(output_slice[0], expected_value1);
        assert_eq!(output_slice[1], expected_value2);
    }

    #[test]
    fn test_parse_params_with_non_multiple_of_8_content_length() {
        // Create a test packet with a HIP header and one parameter with content length not a multiple of 8
        // Total packet size: 40 (fixed header) + 16 (param1) = 56 bytes
        const PACKET_SIZE: usize = 56;
        let mut packet_data = [0u8; PACKET_SIZE];

        // Set up the HIP header
        let hip_hdr = unsafe { get_mut_hiphdr_ref_from_array(&mut packet_data) };
        hip_hdr.set_next_hdr(59);
        hip_hdr.set_hdr_len(6); // (56 bytes total - 8 bytes header) / 8 = 6
        hip_hdr.set_packet_type(0x10);
        hip_hdr.set_version(2);
        hip_hdr.set_fixed_bit2(true);

        // Set up the parameter at offset 40
        let param_offset = HipHdr::FIXED_HEADER_SIZE;
        let param_ptr = unsafe { packet_data.as_mut_ptr().add(param_offset) as *mut HipParamTlv };
        unsafe {
            (*param_ptr).type_ = [0x00, 0x01]; // Type 1
            (*param_ptr).len = [0x00, 0x0A]; // Length 10 bytes (1 u64 + 2 bytes)

            // Set content bytes (10 bytes)
            let content_ptr = packet_data.as_mut_ptr().add(param_offset + HipParamTlv::LEN);
            for i in 0..10 {
                *content_ptr.add(i) = (i + 1) as u8;
            }
        }

        // Create an output slice to store the parsed parameters
        let mut output_slice = [0u64; 4];

        // Call parse_params
        let hip_hdr_ref = unsafe { &*(packet_data.as_ptr() as *const HipHdr) };
        let result = unsafe {
            hip_hdr_ref.parse_params(
                packet_data.as_ptr().add(PACKET_SIZE),
                &mut output_slice,
            )
        };

        // Check the result
        assert_eq!(result, 1); // Should parse only 1 u64 value, ignoring the remaining 2 bytes

        // Check the parsed value
        let expected_value = u64::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(output_slice[0], expected_value);
    }
}
