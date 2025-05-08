use crate::headers::{OptionalHeader32, OptionalHeader64, OptionalHeader, FileHeader, DataDirectory};
use std::ptr;
use crate::errors::{Error, Result};
use crate::utils::read_u16;

impl OptionalHeader {
    pub fn parse_optional_header(buffer: &[u8], e_lfanew: usize) -> Result<OptionalHeader> {
        let fh_offset = e_lfanew + 4;
        let oh_offset: usize = fh_offset + std::mem::size_of::<FileHeader>();
        
        let magic = read_u16(&buffer, oh_offset)?;
    
        let optional_header: OptionalHeader = match magic {
            0x10B => OptionalHeader::Header32(unsafe {
                ptr::read_unaligned(buffer.as_ptr().add(oh_offset) as *const OptionalHeader32)
            }),
            0x20B => OptionalHeader::Header64(unsafe {
                ptr::read_unaligned(buffer.as_ptr().add(oh_offset) as *const OptionalHeader64)
            }),
            other => return Err(Error::UnsupportedOptionalHeader(other)),
        };
        Ok(optional_header)
    }


    /// base_of_data exists only in PE32
    #[inline]
    pub fn base_of_data(&self) -> u64 {
        match self {
            OptionalHeader::Header32(h) => h.base_of_data as u64,
            OptionalHeader::Header64(_) => 0,
        }
    }

    /// Data directories (shared between variants)
    #[inline]
    pub fn data_directory(&self) -> &[DataDirectory; 16] {
        match self {
            OptionalHeader::Header32(h) => &h.data_directory,
            OptionalHeader::Header64(h) => &h.data_directory,
        }
    }
}

