use core::{mem, ptr};

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
pub struct AuthHdr {
    pub next_hdr: u8,
    pub payload_len: u8,
    pub reserved: [u8; 2],
    pub spi: [u8; 4],
    pub seq_num: [u8; 4],
}

/// Errors that can occur during Authentication Header parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthHdrError {
    /// Packet data ended unexpectedly, or a declared length exceeds packet boundaries.
    OutOfBounds,
    /// The Authentication Header indicates a length that extends beyond the provided packet data.
    UnexpectedEndOfPacket,
}

impl AuthHdr {
    /// The total size in bytes of the fixed part of the Authentication Header
    pub const LEN: usize = mem::size_of::<AuthHdr>();

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
        self.total_hdr_len().saturating_sub(AuthHdr::LEN)
    }

    /// Parses the variable-length Integrity Check Value (ICV) from an Authentication Header
    /// into a caller-provided slice of `u64`.
    ///
    /// The Authentication Header's `payload_len` field determines the total length of
    /// the AH header, from which the length of the ICV is derived. The ICV is the
    /// data that follows the fixed part of the Authentication Header. This function
    /// reads the ICV data in 8-byte (u64) chunks.
    ///
    /// # Safety
    /// - `header_ptr` must be a valid pointer to the start of an `AuthHdr`
    ///   structure within the packet data. This function relies on this pointer to
    ///   access the `payload_len` field and determine the start of the ICV.
    /// - `packet_end_ptr` must point to the byte *after* the last valid byte
    ///   of the packet data.
    /// - The memory region covered by the Authentication Header, including the ICV,
    ///   as determined by its `payload_len` field (i.e., `(payload_len + 2) * 4` bytes
    ///   from `header_ptr`), must be valid, accessible, and part of the packet data.
    ///
    /// # Arguments
    /// - `header_ptr`: Pointer to the beginning of the `AuthHdr` (Authentication Header)
    ///   in the packet.
    /// - `packet_end_ptr`: Pointer indicating the end of valid packet data.
    /// - `output_icv_slice`: A mutable slice of `u64` where the parsed ICV will be
    ///   written. Data is read from the packet (assumed to be in network byte order)
    ///   and converted to `u64` values (host byte order).
    ///
    /// # Returns
    /// - `Ok(count)`: The number of `u64` elements successfully read from the ICV
    ///   and written into `output_icv_slice`. This count may be zero if the
    ///   `payload_len` indicates no ICV is present. It may also be less than the
    ///   total available ICV data if `output_icv_slice` is too small or if the
    ///   remaining ICV data is not a multiple of 8 bytes.
    /// - `Err(AuthHdrError)`: If an error occurs during parsing, such as:
    ///     - `AuthHdrError::OutOfBounds`: If reading the fixed part of the `AuthHdr`
    ///       (to access `payload_len`) would go beyond `packet_end_ptr`.
    ///     - `AuthHdrError::UnexpectedEndOfPacket`: If the total AH length defined by
    ///       `payload_len` extends beyond `packet_end_ptr`.

    pub unsafe fn parse_integrity_check_value_to_u64_slice(
        header_ptr: *const AuthHdr,
        packet_end_ptr: *const u8,
        output_icv_slice: &mut [u64],
    ) -> Result<usize, AuthHdrError> {

        if (header_ptr as *const u8).add(AuthHdr::LEN) > packet_end_ptr {
            return Err(AuthHdrError::OutOfBounds);
        }

        // Read payload_len.
        let payload_len_ptr = ptr::addr_of!((*header_ptr).payload_len);
        let payload_len_be = unsafe { ptr::read_unaligned(payload_len_ptr) };
        let payload_len_val = u8::from_be(payload_len_be) as usize;

        // Calculate total header length and verify against packet boundaries.
        let total_hdr_len = (payload_len_val + 2) << 2;
        if (header_ptr as *const u8).add(total_hdr_len) > packet_end_ptr {
            return Err(AuthHdrError::UnexpectedEndOfPacket);
        }
        
        if total_hdr_len <= AuthHdr::LEN {
            return Ok(0);
        }

        // Determine start and end pointers for ICV data.
        let mut current_icv_ptr = (header_ptr as *const u8).add(AuthHdr::LEN);
        let icv_end_ptr = (header_ptr as *const u8).add(total_hdr_len);
        let mut icv_packed_count: usize = 0;
        
        while current_icv_ptr < icv_end_ptr {

            if icv_packed_count >= output_icv_slice.len() {
                break;
            }

            // Check if there are enough bytes remaining in the ICV section
            if current_icv_ptr.add(mem::size_of::<u64>()) > icv_end_ptr {
                break;
            }
            
            let mut packed_icv_bytes = [0u8; 8];

            // Read 8 bytes from current_icv_ptr into packed_icv_bytes.
            ptr::copy_nonoverlapping(
                current_icv_ptr,             // Source pointer from packet data
                packed_icv_bytes.as_mut_ptr(), // Destination buffer
                mem::size_of::<u64>()        // Length to copy (8 bytes)
            );

            // Advance current_icv_ptr by the number of bytes read.
            current_icv_ptr = current_icv_ptr.add(mem::size_of::<u64>());

            // Convert the 8 bytes into a u64.
            output_icv_slice[icv_packed_count] = u64::from_be_bytes(packed_icv_bytes);
            icv_packed_count += 1;
        }

        Ok(icv_packed_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a mutable AuthHdr reference from a mutable byte array.
    unsafe fn get_mut_authhdr_ref_from_array<const N: usize>(data: &mut [u8; N]) -> &mut AuthHdr {
        assert!(N >= AuthHdr::LEN, "Array too small to cast to AuthHdr for testing");
        &mut *(data.as_mut_ptr() as *mut AuthHdr)
    }

    #[test]
    fn test_authhdr_getters_and_setters() {
        const BUF_SIZE: usize = AuthHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let auth_hdr = unsafe { get_mut_authhdr_ref_from_array(&mut packet_buf) };

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
    fn test_authhdr_length_calculation_methods() {
        const BUF_SIZE: usize = AuthHdr::LEN;
        let mut packet_buf = [0u8; BUF_SIZE];
        let auth_hdr = unsafe { get_mut_authhdr_ref_from_array(&mut packet_buf) };

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
        assert_eq!(auth_hdr.icv_len(), (255 + 2) * 4 - AuthHdr::LEN);
    }

    #[test]
    fn test_parse_icv_when_payload_len_is_zero() {
        const PACKET_SIZE: usize = AuthHdr::LEN; // 12 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            6, 0, // next_hdr, payload_len = 0
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
        ];

        let header_ptr = packet_data.as_ptr() as *const AuthHdr;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            AuthHdr::parse_integrity_check_value_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_parse_icv_error_out_of_bounds_on_short_packet() {
        const PACKET_SIZE: usize = 1; // Packet too short for initial read of payload_len
        let packet_data: [u8; PACKET_SIZE] = [6];

        let header_ptr = packet_data.as_ptr() as *const AuthHdr;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            AuthHdr::parse_integrity_check_value_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Err(AuthHdrError::OutOfBounds));
    }

    #[test]
    fn test_parse_icv_error_unexpected_end_of_packet() {
        const PACKET_SIZE: usize = 12;
        // payload_len = 3 implies a 20-byte AH header, but packet data is only 12 bytes.
        let packet_data: [u8; PACKET_SIZE] = [
            6, 3, // next_hdr, payload_len = 3 (implies (3+2)*4 = 20 bytes total AH)
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
        ];

        let header_ptr = packet_data.as_ptr() as *const AuthHdr;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            AuthHdr::parse_integrity_check_value_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Err(AuthHdrError::UnexpectedEndOfPacket));
    }

    #[test]
    fn test_parse_icv_one_chunk_exact_ah_and_packet_length() {
        const PACKET_SIZE: usize = 20; // AH is 20 bytes, ICV = 8 bytes
        let packet_data: [u8; PACKET_SIZE] = [
            6, 3, // next_hdr, payload_len = 3 (total AH 20 bytes)
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
            // ICV (8 bytes)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];

        let header_ptr = packet_data.as_ptr() as *const AuthHdr;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1];

        let result = unsafe {
            AuthHdr::parse_integrity_check_value_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(1));
        let expected_u64 = u64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(output_slice[0], expected_u64);
    }

    #[test]
    fn test_parse_icv_multiple_chunks_exact_ah_and_packet_length() {
        const PACKET_SIZE: usize = 28; // AH is 28 bytes, ICV = 16 bytes (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            6, 5, // next_hdr, payload_len = 5 (total AH 28 bytes)
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
            // ICV Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // ICV Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let header_ptr = packet_data.as_ptr() as *const AuthHdr;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 2];

        let result = unsafe {
            AuthHdr::parse_integrity_check_value_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(2));
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22]));
        assert_eq!(output_slice[1], u64::from_be_bytes([0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00]));
    }

    #[test]
    fn test_parse_icv_output_slice_is_too_small() {
        const PACKET_SIZE: usize = 28; // AH has 16 bytes of ICV (2 chunks)
        let packet_data: [u8; PACKET_SIZE] = [
            6, 5, // next_hdr, payload_len = 5 (total AH 28 bytes)
            0, 0, // reserved
            1, 2, 3, 4, // spi
            5, 6, 7, 8, // seq_num
            // ICV Chunk 1
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
            // ICV Chunk 2
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];

        let header_ptr = packet_data.as_ptr() as *const AuthHdr;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_slice = [0u64; 1]; // Only space for one u64.

        let result = unsafe {
            AuthHdr::parse_integrity_check_value_to_u64_slice(header_ptr, packet_end_ptr, &mut output_slice)
        };
        assert_eq!(result, Ok(1));
        assert_eq!(output_slice[0], u64::from_be_bytes([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22]));
    }
}
