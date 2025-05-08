use serde::Serialize;

use crate::parser::PeFile;
use crate::errors::{Error, Result};
use crate::utils::{rva_to_offset, read_u32};


#[derive(Debug, Serialize)]
pub struct ImportEntry {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}
// to get into import_table, we have first get rva, next find the right section and calculate offset.
pub fn parse_import_table(pe: &PeFile) -> Result<Vec<ImportEntry>> {
    let import_data_directory = pe.optional_header.data_directory()[1];
    let rva = import_data_directory.virtual_address;
    let size = import_data_directory.size as usize;

    let import_table_offset = rva_to_offset(&pe, rva).ok_or(Error::InvalidTableOffset)?;
    let slice_bytes = pe.buffer.get(import_table_offset..import_table_offset + size).ok_or(Error::InvalidTableOffset)?;

    const DESCRIPTOR_SIZE: usize = 5 * 4; // 5 fields every field has 4 bytes
    let mut position = 0; 

    let mut import_table_structure: Vec<ImportEntry> = Vec::new();

    while position * DESCRIPTOR_SIZE < slice_bytes.len() {
        let start = position * DESCRIPTOR_SIZE;
        let end = start + DESCRIPTOR_SIZE;
        let block = &slice_bytes[start..end];

        let original_first_thunk = read_u32(block, 0)?;
        let time_date_stamp = read_u32(block, 4)?;
        let forwarder_chain = read_u32(block, 8)?;
        let name = read_u32(block, 12)?;
        let first_thunk = read_u32(block, 16)?;

        //last descripctor record has all fields == 0, which marks the end of the import table
        if original_first_thunk == 0 && time_date_stamp == 0 && forwarder_chain == 0 && name == 0 && first_thunk == 0 {
            break;
        }

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

