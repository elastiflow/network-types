use core::ptr;

pub(crate) unsafe fn read_u64_chunks(
    start_ptr: *const u8,
    end_ptr: *const u8,
    buffer: &mut [u64],
    chunk_len: usize,
) -> usize {
    let mut current_ptr = start_ptr;
    let mut count = 0;

    while current_ptr < end_ptr && count < buffer.len() {
        if current_ptr.add(chunk_len) > end_ptr {
            break; // Not enough data for a full u64 word.
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
    count
}
