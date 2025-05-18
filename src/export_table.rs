use serde::Serialize;
use crate::{errors::{Error, Result}, parser::PeFile};
use crate::utils::{rva_to_offset, read_u16, read_u32};

/// Represents a single entry in the PE export directory.
///
/// Each entry contains metadata about exported functions, including
/// the DLL name, ordinal base, and RVA addresses of names and functions.
#[derive(Debug, Serialize)]
pub struct ExportEntry {
    /// Characteristics flags set for the export directory (usually 0).
    pub characteristics: u32,
    /// Timestamp indicating when the export data was created (link time).
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    /// RVA of the null-terminated ASCII name of the DLL.
    pub name: u32,
    /// Starting ordinal number for exported functions.
    pub base: u32,
    /// Total number of function entries.
    pub number_of_functions: u32,
    /// Number of names associated with the exports.
    pub number_of_names: u32,
    /// RVA pointing to an array of exported function addresses.
    pub address_of_functions: u32,
    /// RVA pointing to an array of function names.
    pub address_of_names: u32,
    /// RVA pointing to an array of ordinals (one per name).
    pub address_of_name_ordinals: u32,
}

/// Parses the export table from a PE file and returns a list of entries.
///
/// This reads the export directory from the first data directory entry (`data_directory[0]`)
/// and extracts all fixed-size export table structures it can find. The caller is responsible
/// for resolving RVAs like `name` and `address_of_functions` later if needed.
///
/// # Errors
///
/// Returns [`Error::InvalidTableOffset`] if the export directory’s RVA or size are invalid
/// or if any of the reads go out of bounds.
pub fn parse_export_table(pe: &PeFile) -> Result<Vec<ExportEntry>> {
    let export_data_directory = pe.optional_header.data_directory()[0];
    let rva  = export_data_directory.virtual_address;
    let size = export_data_directory.size as usize;

    let export_table_offset = rva_to_offset(pe, rva)
        .ok_or(Error::InvalidTableOffset)?;

    let slice_bytes: &[u8] = pe.buffer
        .get(export_table_offset..export_table_offset + size)
        .ok_or(Error::InvalidTableOffset)?;

    const DESCRIPTOR_SIZE: usize = 9 * 4 + 2 * 2;
    let mut position = 0;
    let mut export_table_structure = Vec::new();

    while position * DESCRIPTOR_SIZE < slice_bytes.len() {
        let start = position * DESCRIPTOR_SIZE;
        let end   = start + DESCRIPTOR_SIZE;
        let block = &slice_bytes[start..end];

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
