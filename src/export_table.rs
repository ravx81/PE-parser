use core::slice;

use crate::{errors::{Error, Result}, parser::PeFile, utils::rva_to_offset};

pub fn parse_export_table(pe: &PeFile) -> Result<()> {
    let export_data_directory = pe.optional_header.data_directory()[0];
    let rva = export_data_directory.virtual_address;
    let size = export_data_directory.size as usize;

    let export_table_offset = rva_to_offset(&pe, rva).ok_or(Error::InvalidExportTableOffset)?;

    let slice_bytes = &pe.buffer[export_table_offset..export_table_offset + size];

    let descriptor_size: usize = 9 * 4 + 2 * 2;

    let mut position = 0;

    while position + descriptor_size <= slice_bytes.len(){
        let start = position * descriptor_size;
        let end = start + descriptor_size;

        let block = &slice_bytes[start..end];

        let characteristics = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let major_version = u16::from_le_bytes(block[8..10].try_into().unwrap());
        let minor_version = u16::from_le_bytes(block[10..12].try_into().unwrap());
        let name = u32::from_le_bytes(block[12..16].try_into().unwrap());
        let base = u32::from_le_bytes(block[16..20].try_into().unwrap());
        let number_of_functions = u32::from_le_bytes(block[20..24].try_into().unwrap());
        let number_of_names = u32::from_le_bytes(block[24..28].try_into().unwrap());
        let address_of_functions = u32::from_le_bytes(block[28..32].try_into().unwrap());
        let address_of_names = u32::from_le_bytes(block[32..36].try_into().unwrap());
        let address_of_name_ordinals = u32::from_le_bytes(block[36..40].try_into().unwrap());
        
    }


    Ok(0)
}