use core::slice;

use serde::Serialize;

use crate::{errors::{Error, Result}, parser::PeFile};
use crate::utils::{rva_to_offset, read_u16, read_u32};

#[derive(Debug, Serialize)]
pub struct ExportEntry {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32, 
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

pub fn parse_export_table(pe: &PeFile) -> Result<Vec<ExportEntry>> {
    let export_data_directory = pe.optional_header.data_directory()[0];
    let rva = export_data_directory.virtual_address;
    let size = export_data_directory.size as usize;

    let export_table_offset = rva_to_offset(&pe, rva).ok_or(Error::InvalidTableOffset)?;

    let slice_bytes = &pe.buffer[export_table_offset..export_table_offset + size];

    const DESCRIPTOR_SIZE: usize = 9 * 4 + 2 * 2; // 9 fields every field has 4 bytes + 2 fields with 2 bytes
    let mut position = 0;
    let mut export_table_structure: Vec<ExportEntry> = Vec::new();

    while position * DESCRIPTOR_SIZE < slice_bytes.len() {
        let start = position * DESCRIPTOR_SIZE;
        let end = start + DESCRIPTOR_SIZE;
        let block = &slice_bytes[start..end];

        let characteristics = read_u32(block, 0)?;
        let time_date_stamp = read_u32(block, 4)?;
        let major_version = read_u16(block, 8)?; 
        let minor_version = read_u16(block, 10)?; 
        let name = read_u32(block, 12)?;
        let base = read_u32(block, 16)?;
        let number_of_functions = read_u32(block, 20)?;
        let number_of_names = read_u32(block, 24)?;
        let address_of_functions = read_u32(block, 28)?;
        let address_of_names = read_u32(block, 32)?;
        let address_of_name_ordinals = read_u32(block, 36)?;

        let export_entry = ExportEntry {
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            name,
            base,
            number_of_functions,
            number_of_names,
            address_of_functions,
            address_of_names,
            address_of_name_ordinals,
        };
        export_table_structure.push(export_entry);

        position += 1;
    }
    Ok(export_table_structure)
}