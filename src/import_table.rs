use chrono::offset;

use crate::parser::PeFile;
use crate::headers::{DosHeader, FileHeader, NtHeaders64, OptionalHeader32, OptionalHeader64, SectionHeader, PE_SIGNATURE};
use crate::errors::{Error, Result};

// to get into import_table, we have first get rva, next find the right section and calculate offset.
pub fn parse_import_table(pe: &PeFile) -> Result<()>{

    let import_data_directory = pe.optional_header.data_directory()[1];
    let rva = import_data_directory.virtual_address;
    let size = import_data_directory.size as usize;

    let import_table_offset = pe.rva_to_offset(rva).ok_or(Error::InvalidImportTableOffset)?;


    let slice_bytes = &pe.buffer[import_table_offset..import_table_offset + size];

    let descriptor_size = 5 * 4; // 5 fields every field has 4 bytes
    let mut position = 0; //we will use loop to go to end of slice_bytes

    while position + descriptor_size <= slice_bytes.len(){
        let start = position * descriptor_size;
        let end = start + descriptor_size;
        let block = &slice_bytes[start..end];

        let original_first_thunk = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let forwarder_chain = u32::from_le_bytes(block[8..12].try_into().unwrap());
        let name = u32::from_le_bytes(block[12..16].try_into().unwrap());
        let first_thunk = u32::from_le_bytes(block[16..20].try_into().unwrap());
        
        let dll_name = read_dll_names(&pe, rva)?;
        
    }
    
    Ok(())
}
pub fn read_dll_names(pe: &PeFile, rva: u32) -> Result<String>{
    //change RVA to offset in file
    let offset = pe.rva_to_offset(rva).ok_or(Error::InvalidImportTableOffset)?;
    //we take from beginning to end, because we don't know where ('0x00') is.
    let buffer = &pe.buffer[offset..];
    //search for first ('0x00') that means it is end of dll_name
    let buffer_len = buffer.iter().position(|&byte| byte == 0).unwrap_or(buffer.len());
    // just convert to string, from bytes
    let dll_name = std::str::from_utf8(&buffer[..buffer_len]).map_err(|_| Error::InvalidDllName)?.to_string();

    Ok(dll_name)
}
