use core::ptr;

/// Errors that can occur during Authentication Header parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkReaderError {
    /// The Authentication Header indicates a length that extends beyond the provided packet data.
    /// The attached `usize` values indicate the number of bytes that were successfully read (`bytes_read`)
    /// and total bytes attempted to read (`count`) before the unexpected end of the packet.
    UnexpectedEndOfPacket { bytes_read: usize, count: usize },
    /// This variant can be used if `chunk_len` is not equal to `mem::size_of::<u64>()`
    /// which would cause issues with `u64::from_be_bytes`.
    InvalidChunkLength { expected: usize, found: usize },
}

pub(crate) unsafe fn read_u64_chunks(
    start_ptr: *const u8,
    end_ptr: *const u8,
    buffer: &mut [u64],
    chunk_len: usize,
) -> Result<usize, ChunkReaderError> {
    if chunk_len != core::mem::size_of::<u64>() {
        return Err(ChunkReaderError::InvalidChunkLength {
            expected: core::mem::size_of::<u64>(),
            found: chunk_len,
        });
    }

    let mut current_ptr = start_ptr;
    let mut count = 0;

    while current_ptr < end_ptr && count < buffer.len() {
        if current_ptr.add(chunk_len) > end_ptr {
            // not enough data for a complete chunk.
            return Err(ChunkReaderError::UnexpectedEndOfPacket { bytes_read: count * chunk_len, count });
        }

        let mut block_bytes = [0u8; 8]; // u64 is 8 bytes
        ptr::copy_nonoverlapping(
            current_ptr,
            block_bytes.as_mut_ptr(),
            chunk_len,
        );

        buffer[count] = u64::from_be_bytes(block_bytes);

        current_ptr = current_ptr.add(chunk_len);
        count += 1;
    }
    Ok(count)
}
