use std::path::Path;
use crate::headers::{DosHeader, FileHeader, OptionalHeader, SectionHeader, PE_SIGNATURE};
use crate::view::Parsed;
use serde::Serialize;
use crate::errors::{Error, Result};
use crate::utils::{read_u32, read_u16};

/// Loaded PE file with its main headers and sections.
#[derive(Serialize)]
pub struct PeFile {
    /// Entire file contents.
    #[serde(skip_serializing)]
    pub buffer: Vec<u8>,

    /// Offset to the NT header (e_lfanew).
    #[serde(skip_serializing)]
    pub e_lfanew: usize,

    /// COFF FileHeader.
    pub file_header: FileHeader,

    /// OptionalHeader (32- or 64-bit).
    pub optional_header: OptionalHeader,

    /// Section headers table.
    pub sections: Vec<SectionHeader>,
}

impl PeFile {
    /// Verify DOS header size and PE signature.
    ///
    /// Returns an error if the file is too short or the PE signature is invalid.
    fn validate(&self) -> Result<()> {
        let buf = &self.buffer;
        if buf.len() < 0x40 {
            return Err(Error::InvalidSize { expected: 0x40, found: buf.len() });
        }

        let sig = read_u32(buf, self.e_lfanew)?;
        if sig != PE_SIGNATURE {
            return Err(Error::InvalidPeSignature(sig));
        }

        Ok(())
    }

    /// Read a PE file from `path`, parse headers and sections, and validate signature.
    ///
    /// # Errors
    /// Returns an error if I/O fails, headers are malformed, or validation fails.
    pub fn parse(path: &Path) -> Result<Self> {
        let buffer         = std::fs::read(path)?;
        let dos_header     = DosHeader::parse(&buffer)?;
        let e_lfanew       = dos_header.e_lfanew();
        let file_header    = FileHeader::parse_file_header(&buffer, e_lfanew)?;
        let optional_header= OptionalHeader::parse_optional_header(&buffer, e_lfanew)?;
        let sections       = SectionHeader::parse_section_headers(&buffer, &file_header, e_lfanew)?;

        let pe = PeFile {
            buffer,
            e_lfanew,
            file_header,
            optional_header,
            sections,
        };

        pe.validate()?;
        Ok(pe)
    }

    /// Return a reference to this `PeFile`.
    pub fn raw(&self) -> &Self {
        self
    }

    /// Wrap this file in a `Parsed` view for JSON output.
    pub fn parsed(&self) -> Parsed<'_> {
        Parsed::new(self)
    }
}
