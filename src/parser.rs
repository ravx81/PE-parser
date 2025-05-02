use std::{ptr, fs};
use std::convert::TryInto;
use crate::headers::{DataDirectory, FileHeader,  OptionalHeader32, OptionalHeader64, SectionHeader, PE_SIGNATURE};
use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use crate::errors::{Error, Result};
use std::mem::size_of;
pub enum OptionalHeader {
    Header32(OptionalHeader32),
    Header64(OptionalHeader64),
}


pub struct PeFile {
    pub buffer: Vec<u8>, //whole memory in file
    pub e_lfanew: usize,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
}

impl OptionalHeader {
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
impl PeFile{
    pub fn parse(path: &str) -> Result<Self> {
        let buffer = fs::read(path)?;
        Self::validate_dos(&buffer)?;
        let e_lfanew = Self::dos_e_lfanew(&buffer)?;

        let file_header   = Self::parse_file_header(&buffer, e_lfanew)?;
        let optional_header  = Self::parse_optional_header(&buffer, e_lfanew)?;
        Self::validate_pe_signature(&buffer, e_lfanew)?;

        Ok(Self {
            buffer,
            e_lfanew,
            file_header,
            optional_header: optional_header,
        })
    }
    fn validate_dos(buffer: &[u8]) -> Result<()> {
        let dos_magic = u16::from_le_bytes(buffer[0..2].try_into().unwrap());
        if dos_magic != 0x5A4D {
            return Err(Error::InvalidMagic(dos_magic));
        }
        Ok(())
    }
    fn dos_e_lfanew(buffer: &[u8]) -> Result<usize> {
        let e_lfanew = {
            let bytes: [u8; 4] = buffer[0x3C..0x40].try_into().unwrap();
            u32::from_le_bytes(bytes) as usize
        };
        Ok(e_lfanew)
    }
    fn parse_file_header(buffer: &[u8], e_lfanew: usize) -> Result<FileHeader> {
        let fh_offset = e_lfanew + 4;
        let file_header: FileHeader = unsafe {
            //we read here struct from headers.rs (20 bytes)
            ptr::read_unaligned(buffer.as_ptr().add(fh_offset) as *const FileHeader)
        };
        Ok(file_header)
    }
    fn parse_optional_header(buffer: &[u8], e_lfanew: usize) -> Result<OptionalHeader> {
        let fh_offset = e_lfanew + 4;
        let oh_offset: usize = fh_offset + std::mem::size_of::<FileHeader>();
        
        let magic = u16::from_le_bytes(buffer[oh_offset..oh_offset+2].try_into().unwrap());

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
    fn validate_pe_signature(buffer: &[u8], e_lfanew: usize) -> Result<()> {
        let pe_signature_bytes: [u8; 4] = buffer[e_lfanew..e_lfanew+4].try_into().unwrap();

        let pe_signature = u32::from_le_bytes(pe_signature_bytes);

        if pe_signature != PE_SIGNATURE{
            return Err(Error::InvalidPeSignature(pe_signature));
        }
        Ok(())
    }

    pub fn parse_section_headers(&self) -> Vec<SectionHeader>{
        //section_offset = e_lfanew + PE_signature... 
        let section_offset = self.e_lfanew + 4 + size_of::<crate::headers::FileHeader>() + self.file_header.size_of_optional_header as usize;
        let number_of_sections = self.file_header.number_of_sections as usize;
        let mut sections = Vec::with_capacity(number_of_sections);

        // first section_header stars here
        let base_ptr = unsafe { self.buffer.as_ptr().add(section_offset) as *const SectionHeader};

        for i in 0..number_of_sections{
            let ptr_section = unsafe {base_ptr.add(i)};

            let section = unsafe {ptr::read_unaligned(ptr_section)};

            sections.push(section);
        }
        sections
    }
}




