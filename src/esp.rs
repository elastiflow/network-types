/// # Encapsulating Security Payload (ESP) - Initial Header Fields
///
/// | Offset | Octet 0       | Octet 1       | Octet 2       | Octet 3       |
/// |--------|---------------|---------------|---------------|---------------|
/// | 0      | Security Parameters Index (bits 0-7) | Security Parameters Index (bits 8-15) | Security Parameters Index (bits 16-23) | Security Parameters Index (bits 24-31) |
/// | 4      | Sequence Number (bits 0-7) | Sequence Number (bits 8-15) | Sequence Number (bits 16-23) | Sequence Number (bits 24-31) |
///
/// ## Fields
///
/// * **Security Parameters Index (SPI) (32 bits)**: An arbitrary value used to uniquely identify the **security association** of the receiving party. 
/// * **Sequence Number (32 bits)**: A monotonically increasing counter for protecting against **replay attacks**.

use core::mem;

/// Encapsulating Security Payload (ESP) Header
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Esp {
    pub spi: [u8; 4],
    pub seq_num: [u8; 4],
}

impl Esp {
    /// The total size in bytes of the ESP header
    pub const LEN: usize = mem::size_of::<Esp>();

    /// Gets the Security Parameters Index (SPI) value.
    pub fn spi(&self) -> u32 {
        u32::from_be_bytes(self.spi)
    }

    /// Sets the Security Parameters Index (SPI) value.
    pub fn set_spi(&mut self, spi: u32) {
        self.spi = spi.to_be_bytes();
    }

    /// Gets the Sequence Number value.
    pub fn seq_num(&self) -> u32 {
        u32::from_be_bytes(self.seq_num)
    }

    /// Sets the Sequence Number value.
    pub fn set_seq_num(&mut self, seq_num: u32) {
        self.seq_num = seq_num.to_be_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_len_constant() {
        assert_eq!(Esp::LEN, 8); // spi (4 bytes) + seq_num (4 bytes)
        assert_eq!(Esp::LEN, mem::size_of::<Esp>());
    }

    #[test]
    fn test_getters_setters() {
        let mut header = Esp {
            spi: [0; 4],
            seq_num: [0; 4],
        };

        // Test SPI
        header.set_spi(0x12345678);
        assert_eq!(header.spi(), 0x12345678);
        assert_eq!(header.spi, [0x12, 0x34, 0x56, 0x78]);

        // Test Sequence Number
        header.set_seq_num(0x87654321);
        assert_eq!(header.seq_num(), 0x87654321);
        assert_eq!(header.seq_num, [0x87, 0x65, 0x43, 0x21]);
    }
}
