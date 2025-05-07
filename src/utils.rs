
use crate::parser::PeFile;
use crate::headers::{FileHeader, SectionHeader};
use crate::errors::{Error, Result};



pub fn rva_to_offset(pe: &PeFile, rva: u32) -> Option<usize> {
    for section in &pe.sections{
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
pub fn read_u32(block: &[u8], offset: usize) -> Result<u32> {
    let expected_size = 4;
    block
        .get(offset..offset + expected_size)
        .ok_or(Error::InvalidSize { expected: expected_size, found: block.len() })?  // Zainicjalizowanie struktury
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| Error::InvalidData)
}

pub fn read_u16(block: &[u8], offset: usize) -> Result<u16> {
    let expected_size = 2;
    block
        .get(offset..offset + expected_size)
        .ok_or(Error::InvalidSize {expected: expected_size, found: block.len() })?
        .try_into()
        .map(u16::from_le_bytes)
        .map_err(|_| Error::InvalidData)
}
