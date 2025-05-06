use chrono::offset;
use serde::Serialize;

use crate::parser::PeFile;
use crate::headers::{DosHeader, FileHeader, NtHeaders64, OptionalHeader32, OptionalHeader64, SectionHeader, PE_SIGNATURE};
use crate::errors::{Error, Result};
use crate::utils::{read_dll_names, rva_to_offset};


#[derive(Debug, Serialize)]
pub struct ImportEntry {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}
// to get into import_table, we have first get rva, next find the right section and calculate offset.
pub fn parse_import_table(pe: &PeFile) -> Result<Vec<ImportEntry>>{

    let import_data_directory = pe.optional_header.data_directory()[1];
    let rva = import_data_directory.virtual_address;
    let size = import_data_directory.size as usize;

    let import_table_offset = rva_to_offset(&pe, rva).ok_or(Error::InvalidTableOffset)?;


    let slice_bytes = &pe.buffer[import_table_offset..import_table_offset + size];

    let descriptor_size = 5 * 4; // 5 fields every field has 4 bytes
    let mut position = 0; //we will use loop to go to end of slice_bytes

    let mut import_table_structure: Vec<ImportEntry> = Vec::new();
    while position + descriptor_size <= slice_bytes.len(){
        let start = position * descriptor_size;
        let end = start + descriptor_size;
        let block = &slice_bytes[start..end];

        let original_first_thunk = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let forwarder_chain = u32::from_le_bytes(block[8..12].try_into().unwrap());
        let name = u32::from_le_bytes(block[12..16].try_into().unwrap());
        let first_thunk = u32::from_le_bytes(block[16..20].try_into().unwrap());
        //last descripctor record has all fields == 0, which marks the end of the import table
        if original_first_thunk == 0 && time_date_stamp == 0 && forwarder_chain == 0 && name == 0 && first_thunk == 0 {break;}

        //let dll_name = read_dll_names(&pe, name)?;

        let import_entry = ImportEntry {
            original_first_thunk,
            time_date_stamp,
            forwarder_chain,
            name,
            first_thunk,
        };
        import_table_structure.push(import_entry);


        position += 1;
    
    }   
    Ok(import_table_structure)
}

