use crate::headers::FileHeader;
use std::ptr;
use crate::errors::Result;



impl FileHeader {
    /// Grab the 20‑byte **COFF FileHeader** that lives right after the PE signature.
    ///
    // # Safety
    ///
    /// This does an unaligned, direct memory read of the `#[repr(C)]` struct.
    /// The caller must guarantee that:
    /// - `buffer.len() >= std::mem::size_of::<FileHeader>()` (20 bytes),  
    /// - `buffer` actually begins with a valid File header.
    pub fn parse_file_header(buffer: &[u8], e_lfanew: usize) -> Result<FileHeader> {
        let fh_offset = e_lfanew + 4;
        let header = unsafe {
            ptr::read_unaligned(buffer.as_ptr().add(fh_offset) as *const FileHeader)
        };
        Ok(header)
    }
}

