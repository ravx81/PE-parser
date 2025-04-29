use core::error;
use std::{io, ptr, result, vec};
use std::{fmt::format, fs};
use std::convert::TryInto;
use crate::headers::{DosHeader, FileHeader, NtHeaders64, OptionalHeader32, OptionalHeader64, SectionHeader, PE_SIGNATURE};
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
    buffer: Vec<u8>, //whole memory in file
    e_lfanew: usize,
    file_header: FileHeader,
    optional_header: Box<dyn OptionalHeaderView>,
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
    //from fileheader
    }
    pub fn number_of_sections(&self) -> u16 {
        self.file_header.number_of_sections
    }
    
    pub fn timestamp(&self) -> String {
        let d = UNIX_EPOCH + Duration::from_secs(self.file_header.time_date_stamp as u64);
        let datetime = DateTime::<Utc>::from(d);
        let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
        timestamp_str
    }
    pub fn characteristics(&self) -> u16 {
        self.file_header.characteristics
    }
    pub fn architecture(&self) -> &'static str {
        let machine_offset = self.e_lfanew + 4;
        let raw_arch = u16::from_le_bytes(self.buffer[machine_offset..machine_offset+2 ].try_into().expect("shit"));

        match raw_arch {
            0x014c => "x86 (32‑bit)",
            0x8664 => "x64 (64‑bit)",
            0x1c0  => "ARM",
            0xaa64 => "ARM64",
            _      => "Unknowed architecture",
        }
    }

    //from optionalheader

    pub fn adres_of_entry_point(&self) -> u32 {
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
    
    pub fn subsystem(&self) -> &str { 
        let number = self.optional_header.subsystem();
        let result = match number{
            2 => "Windows GUI (2)",
            3 => "Windows Console (3)",
            9 => "Windows CE GUI (9)",
            _ => "Unknowed number",
        };
        result
    }
    pub fn dll_characteristics(&self) -> Vec<(u16, &'static str)> { 
        let flag = self.optional_header.dll_characteristics();
        let mut results = Vec::new();
        let flag_descriptions = [
            (0x0020, "HIGH_ENTROPY_VA"),
            (0x0040, "DYNAMIC_BASE (ASLR)"),
            (0x0080, "FORCE_INTEGRITY"),
            (0x0100, "NX_COMPAT (DEP)"),
            (0x0200, "NO_ISOLATION"),
            (0x0400, "NO_SEH"),
            (0x0800, "NO_BIND"),
            (0x1000, "APPCONTAINER"),
            (0x2000, "WDM_DRIVER"),
            (0x4000, "GUARD_CF"),
            (0x8000, "TERMINAL_SERVER_AWARE"),
            ];
        for (mask, description) in &flag_descriptions{
            if flag & mask != 0{
                results.push((*mask, *description));
            }
        }
        results
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
    pub fn read_sections(&self, section_name: &str) -> Vec<u8>{
        
    }
    pub fn print_file_header(&self){
        println!("FILE HEADER: \n --------------------- ");
        println!("Machine: {}", self.architecture());
        println!("Number of sections: {}", self.number_of_sections());
        println!("Time date stamp: {}", self.timestamp());
        println!("Characteristic: {}", self.characteristics());
    }
    pub fn print_optional_header(&self){
        println!("OPTIONAL HEADER: \n --------------------- ");
        println!("Address of entry point: {}", self.adres_of_entry_point());
        println!("Image base: {}", self.image_base());
        println!("Section aligment: {}", self.section_alignment());
        println!("File alignment: {}", self.file_alignment());
        println!("Size of image: {}", self.size_of_image());
        println!("Size of headers: {}", self.size_of_headers());
        println!("Sub system: {}", self.subsystem());
        println!("Dll characteristic: ");
        for (mask, desc) in self.dll_characteristics(){
            println!("Flag: 0x{:04x} - {}", mask, desc);
        }
    }
    pub fn print_section_headers(&self){
        println!("SECTION HEADERS: \n --------------------- ");
        for section in self.parse_section_headers(){
            let name = String::from_utf8_lossy(&section.name).to_string();
            println!("{}", name);
            println!("Virtual size: {}", section.virtual_size);
            println!("Virtual address {}", section.virtual_address);
            println!("Size of raw data {}", section.size_of_raw_data);
            println!("Pointer to raw data {}", section.pointer_to_raw_data);
            println!("Characteristics: {}", section.characteristics);
        }
    }
}


