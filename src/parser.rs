use std::path::Path;
use std::{ptr, fs};
use crate::headers::{DataDirectory, DosHeader, FileHeader, OptionalHeader, OptionalHeader32, OptionalHeader64, SectionHeader};
use crate::errors::{Error, Result};
use crate::view::Parsed;

pub struct PeFile {
    pub buffer: Vec<u8>, //whole memory in file
    pub e_lfanew: usize,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<SectionHeader>,
}


impl PeFile {
    pub fn parse(path: &Path) -> Result<Self> {
        let buffer = std::fs::read(path)?;
        let dos_header = DosHeader::parse(&buffer)?;
        let e_lfanew = dos_header.e_lfanew();
        let file_header = FileHeader::parse_file_header(&buffer, e_lfanew)?;
        let optional_header = OptionalHeader::parse_optional_header(&buffer, e_lfanew)?;
        let sections = SectionHeader::parse_section_headers(&buffer, &file_header, e_lfanew)?;
        Ok(PeFile { buffer: buffer, e_lfanew, file_header, optional_header, sections })
    }
    pub fn raw(&self) -> &Self {
        self
    }
    pub fn parsed(&self) -> Parsed{
        Parsed::new(self)
    }

}




