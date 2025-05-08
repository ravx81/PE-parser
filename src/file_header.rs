use crate::{headers::{FileHeader, PE_SIGNATURE}, utils::read_u32};
use std::ptr;
use crate::errors::{Error, Result};

impl FileHeader{
    pub fn parse_file_header(buffer: &[u8], e_lfanew: usize) -> Result<FileHeader> {
        let fh_offset = e_lfanew + 4;
        let file_header: FileHeader = unsafe {
            //we read here struct from headers.rs (20 bytes)
            ptr::read_unaligned(buffer.as_ptr().add(fh_offset) as *const FileHeader)
        };
        Ok(file_header)
    }
} 
