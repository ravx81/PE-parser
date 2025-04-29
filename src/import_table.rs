use chrono::offset;

use crate::parser::PeFile;
use crate::headers::{DosHeader, FileHeader, NtHeaders64, OptionalHeader32, OptionalHeader64, SectionHeader, PE_SIGNATURE};
use crate::errors::{Error, Result};

// to get into import_table, we have first get rva, next find the right section and calculate offset.
pub fn parse_import_table(pe: &PeFile) -> Result<()>{

    let import_data_directory = pe.optional_header.data_directory()[1];
    let rva = import_data_directory.virtual_address;
    let size = import_data_directory.size as usize;

    let sections = pe.parse_section_headers();
    let mut offset: Option<usize> = None;
    //section.virtual.address = 
    //section.pointer_to_raw_data = offset from beginning file, section starts here
    for section in sections{
        //check if rva is in section
        if rva > section.virtual_address && rva < section.virtual_address + section.virtual_size{
            //difference e.g 0x2100 - 0x2000 it gives how many bytes we should move on in memory
            let memory_delta = rva - section.virtual_address;
            // section_start + how many bytes we should move
            offset = Some(section.pointer_to_raw_data as usize + memory_delta as usize);
            break;
        }
    }
    let import_table_offset = offset.ok_or(Error::InvalidImportTableOffset)?;


    let slice_bytes = &pe.buffer[import_table_offset..import_table_offset + size];
    Ok(())
}
