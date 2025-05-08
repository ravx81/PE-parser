use serde::Serialize;
use crate::{errors::{Error, Result}, parser::PeFile};
use crate::utils::{rva_to_offset, read_u16, read_u32};

/// One entry in the PE export table.
#[derive(Debug, Serialize)]
pub struct ExportEntry {
    /// Export characteristics flags (informations about table).
    pub characteristics: u32,
    /// Time of first linking.
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    /// RVA of the ASCII name of the exporting DLL.
    pub name: u32,
    /// Base ordinal number for exports.
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// Parse the export table from a PE file and return its entries.
///
/// # Errors
///
/// Returns `Error::InvalidTableOffset` if the export directory RVA or size.
/// does not map into the file buffer, or if any field read goes out of bounds.
pub fn parse_export_table(pe: &PeFile) -> Result<Vec<ExportEntry>> {
    // Locate the export data directory
    let export_data_directory = pe.optional_header.data_directory()[0];
    let rva  = export_data_directory.virtual_address;
    let size = export_data_directory.size as usize;

    // Map RVA to file offset.
    let export_table_offset = rva_to_offset(pe, rva)
        .ok_or(Error::InvalidTableOffset)?;

    // Ensure the slice is within the buffer
    let slice_bytes: &[u8] = pe.buffer
        .get(export_table_offset..export_table_offset + size)
        .ok_or(Error::InvalidTableOffset)?;
    /// Every field has 4 bytes + 2 fields with 2 bytes.
    const DESCRIPTOR_SIZE: usize = 9 * 4 + 2 * 2;
    let mut position = 0;
    let mut export_table_structure = Vec::new();

    // Iterate over each export directory entry.
    while position * DESCRIPTOR_SIZE < slice_bytes.len() {
        let start = position * DESCRIPTOR_SIZE;
        let end   = start + DESCRIPTOR_SIZE;
        let block = &slice_bytes[start..end];
        //Use function from utils.rs, to check if it's not issue to read date based on offset.
        let characteristics            = read_u32(block, 0)?;
        let time_date_stamp            = read_u32(block, 4)?;
        let major_version              = read_u16(block, 8)?;
        let minor_version              = read_u16(block, 10)?;
        let name                       = read_u32(block, 12)?;
        let base                       = read_u32(block, 16)?;
        let number_of_functions        = read_u32(block, 20)?;
        let number_of_names            = read_u32(block, 24)?;
        let address_of_functions       = read_u32(block, 28)?;
        let address_of_names           = read_u32(block, 32)?;
        let address_of_name_ordinals   = read_u32(block, 36)?;

        export_table_structure.push(ExportEntry {
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
        });
        
        position += 1;
    }

    Ok(export_table_structure)
}
