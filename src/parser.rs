use std::ptr;
use std::{fmt::format, fs};
use std::convert::TryInto;
use crate::headers::{DosHeader, NtHeaders64, PE_SIGNATURE, FileHeader, OptionalHeader32 ,OptionalHeader64};


pub enum OptionalHeader {
    Header32(OptionalHeader32),
    Header64(OptionalHeader64),
}

pub struct PeFile {
    buffer: Vec<u8>,
    e_lfanew: usize,
    file_header: FileHeader,
    optional_header: OptionalHeader,
}

impl PeFile{
    pub fn parse(path: &str) -> Result<Self, String> {
        let buffer = fs::read(path).map_err(|e| format!("Error while reading file: {}", e))?;

        let e_lfanew = {
            let bytes: [u8; 4] = buffer[0x3C..0x40].try_into().unwrap();
            u32::from_le_bytes(bytes) as usize
        };

        let fh_offset = e_lfanew + 4;
        let file_header: FileHeader = unsafe {
            //We read here struct from headers.rs (20 bytes)
            ptr::read_unaligned(buffer.as_ptr().add(fh_offset) as *const FileHeader)
        };

        let oh_offset: usize = fh_offset + std::mem::size_of<FileHeader>();


        let magic = u16::from_le_bytes(buffer[oh_offset..oh_offset+2].try_into().unwrap());

        let optional_header =  match magic {
            0x10B => {
                let optional_header32: OptionalHeader32 = unsafe {
                    ptr::read_unaligned(buffer.as_ptr().add(oh_offset) as *const OptionalHeader32)
                };
                OptionalHeader::Header32(optional_header32)
            }
            0x20B => {
                let optional_header64: OptionalHeader64 = unsafe {
                    ptr::read_unaligned(buffer.as_ptr().add(oh_offset) as *const OptionalHeader64)
                };
                OptionalHeader::Header64(optional_header64)
            }
        };

        Ok(PeFile { buffer, e_lfanew, file_header, optional_header})

    }
}

pub fn detect_architecture(path: &str) -> Result<String, String>{ 
    let buffer = fs::read(path).map_err(|e| format!("Error while reading file: {}", e))?;

    let e_lfanew = {
        let bytes: [u8; 4] = buffer[0x3C..0x40].try_into().unwrap();
        u32::from_le_bytes(bytes) as usize
    };

    let machine = {
        let b: [u8; 2] = buffer[e_lfanew+4..e_lfanew+6].try_into().unwrap();
        u16::from_le_bytes(b)
    };



    let arch = match machine {
        0x014c => "x86 (32‑bit)",
        0x8664 => "x64 (64‑bit)",
        0x1c0  => "ARM",
        0xaa64 => "ARM64",
        _      => "Unknowed architecture",
    };

    Ok(arch.to_string())
}
    

