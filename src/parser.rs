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
    pub optional_header: Box<dyn OptionalHeaderView>,
}

pub trait OptionalHeaderView {
    fn address_of_entry_point(&self) -> u32;
    fn image_base(&self)            -> u64;
    fn size_of_image(&self)         -> u32;
    fn size_of_headers(&self)       -> u32;
    fn section_alignment(&self)     -> u32;
    fn file_alignment(&self)        -> u32;
    fn subsystem(&self)             -> u16;   // możesz zwrócić własny enum Subsystem
    fn dll_characteristics(&self)   -> u16;
    fn data_directory(&self)        -> [DataDirectory; 16];

}

impl OptionalHeaderView for OptionalHeader32 {
    fn address_of_entry_point(&self) -> u32 { self.address_of_entry_point }
    fn image_base(&self)            -> u64 { self.image_base as u64 }

    fn size_of_image(&self)         -> u32 { self.size_of_image }
    fn size_of_headers(&self)       -> u32 { self.size_of_headers }
    fn section_alignment(&self)     -> u32 { self.section_alignment }
    fn file_alignment(&self)        -> u32 { self.file_alignment }

    fn subsystem(&self)             -> u16 { self.subsystem }
    fn dll_characteristics(&self)   -> u16 { self.dll_characteristics }
    fn data_directory(&self)        -> [DataDirectory; 16] { self.data_directory}

}
impl OptionalHeaderView for OptionalHeader64 {
    fn address_of_entry_point(&self) -> u32 { self.address_of_entry_point }
    fn image_base(&self)            -> u64 { self.image_base }

    fn size_of_image(&self)         -> u32 { self.size_of_image }
    fn size_of_headers(&self)       -> u32 { self.size_of_headers }
    fn section_alignment(&self)     -> u32 { self.section_alignment }
    fn file_alignment(&self)        -> u32 { self.file_alignment }

    fn subsystem(&self)             -> u16 { self.subsystem }
    fn dll_characteristics(&self)   -> u16 { self.dll_characteristics }
    fn data_directory(&self)        -> [DataDirectory; 16] { self.data_directory}
}

impl PeFile{
    pub fn parse(path: &str) -> Result<Self> {
        let buffer = fs::read(path)?;
        // checked if "MZ" is in file. 
        let dos_magic = u16::from_le_bytes(buffer[0..2].try_into().unwrap());
        if dos_magic != 0x5A4D {
            return Err(Error::InvalidMagic(dos_magic));
        }

        // DOS header at 0x3C holds e_lfanew (4 bytes)
        let e_lfanew = {
            let bytes: [u8; 4] = buffer[0x3C..0x40].try_into().unwrap();
            u32::from_le_bytes(bytes) as usize
        };
        // file_header
        let fh_offset = e_lfanew + 4;
        let file_header: FileHeader = unsafe {
            //we read here struct from headers.rs (20 bytes)
            ptr::read_unaligned(buffer.as_ptr().add(fh_offset) as *const FileHeader)
        };

        //optional header
        let oh_offset: usize = fh_offset + std::mem::size_of::<FileHeader>();


        let magic = u16::from_le_bytes(buffer[oh_offset..oh_offset+2].try_into().unwrap());
        
        let optional_header: Box<dyn OptionalHeaderView> = match magic {
            0x10B => Box::new(unsafe {
                ptr::read_unaligned(buffer.as_ptr().add(oh_offset) as *const OptionalHeader32)
            }),
            0x20B => Box::new(unsafe {
                ptr::read_unaligned(buffer.as_ptr().add(oh_offset) as *const OptionalHeader64)
            }),
            other => return Err(Error::UnsupportedOptionalHeader(other)),
        };

        let pe_signature_bytes: [u8; 4] = buffer[e_lfanew..e_lfanew+4].try_into().unwrap();

        let pe_signature = u32::from_le_bytes(pe_signature_bytes);

        if pe_signature != PE_SIGNATURE{
            return Err(Error::InvalidPeSignature(pe_signature));
        }

        Ok(Self { buffer, e_lfanew, file_header, optional_header})

    //fileaheader getters
    }
    pub fn number_of_sections(&self) -> u16 {
        self.file_header.number_of_sections
    }
    
    pub fn characteristics(&self) -> u16 {
        self.file_header.characteristics
    }

    //from optionalheader

    pub fn address_of_entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point()
    }
    pub fn image_base(&self) -> u64{
        self.optional_header.image_base()
    }
    pub fn size_of_image(&self) -> u32{
        self.optional_header.size_of_image()
    }
    pub fn size_of_headers(&self) -> u32 { 
        self.optional_header.size_of_headers()
    }
    pub fn section_alignment(&self) -> u32 { 
        self.optional_header.section_alignment()
    }

    pub fn file_alignment(&self) -> u32 { 
        self.optional_header.file_alignment()
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




