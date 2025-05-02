use crate::headers::{FileHeader, PE_SIGNATURE};
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
    
    pub fn validate_pe_signature(buffer: &[u8], e_lfanew: usize) -> Result<()> {
        let pe_signature_bytes: [u8; 4] = buffer[e_lfanew..e_lfanew+4].try_into().unwrap();
    
        let pe_signature = u32::from_le_bytes(pe_signature_bytes);
    
        if pe_signature != PE_SIGNATURE{
            return Err(Error::InvalidPeSignature(pe_signature));
        }
        Ok(())
    }
} 
