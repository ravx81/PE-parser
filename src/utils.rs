
use crate::parser::PeFile;
use crate::errors::{Error, Result};



pub fn rva_to_offset(pe: &PeFile, rva: u32) -> Option<usize> {

        for section in pe.parse_section_headers(){
            //check if rva is in a section
            if rva > section.virtual_address && rva < section.virtual_address + section.virtual_size{
                //difference e.g 0x2100 - 0x2000 it gives how many bytes we should move on in memory
                let memory_delta = rva - section.virtual_address;
                // section_start + how many bytes we should move
                return Some(section.pointer_to_raw_data as usize + memory_delta as usize);
            }
        }
        None
    }

pub fn read_dll_names(pe: &PeFile, rva: u32) -> Result<String>{
    //change RVA to offset in file
    let offset = rva_to_offset(&pe, rva).ok_or(Error::InvalidTableOffset)?;
    //we take from beginning to end, because we don't know where ('0x00') is.
    let buffer = &pe.buffer[offset..];
    //search for first ('0x00') that means it is end of dll_name
    let buffer_len = buffer.iter().position(|&byte| byte == 0).unwrap_or(buffer.len());
    // just convert to string, from bytes
    let dll_name = std::str::from_utf8(&buffer[..buffer_len]).map_err(|_| Error::InvalidDllName)?.to_string();

    Ok(dll_name)
}