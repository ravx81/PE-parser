use serde::Serialize;

use crate::parser::PeFile;
use crate::errors::{Error, Result};
use crate::utils::{rva_to_offset, read_u32};

/// One entry in the PE import table.
#[derive(Debug, Serialize)]
pub struct ImportEntry {
    /// RVA of the original import lookup table (first thunk).
    pub original_first_thunk: u32,
    /// Time of first linking.
    pub time_date_stamp: u32,
    /// Index of the forwarder chain.
    pub forwarder_chain: u32,
    /// RVA of the ASCII name of the imported DLL.
    pub name: u32,
    /// RVA of the import address table (first thunk for IAT).
    pub first_thunk: u32,
}

/// Parse the import table from a PE file and return its entries.
///
/// # Errors
/// Returns `Error::InvalidTableOffset` if the import directory RVA or size
/// does not map into the file buffer, or if any read goes out of bounds.
pub fn parse_import_table(pe: &PeFile) -> Result<Vec<ImportEntry>> {
    // Locate the import data directory (second directory entry)
    let import_dir = pe.optional_header.data_directory()[1];
    let rva = import_dir.virtual_address;
    let size = import_dir.size as usize;

    // Map RVA to file offset
    let offset = rva_to_offset(pe, rva)
        .ok_or(Error::InvalidTableOffset)?;

    // Ensure the slice is within buffer bounds
    let slice = pe.buffer
        .get(offset..offset + size)
        .ok_or(Error::InvalidTableOffset)?;
    /// Five u32 fields, every has 4 bytes.
    const ENTRY_SIZE: usize = 5 * 4; 
    let mut entries = Vec::new();
    let mut pos = 0;

    // Iterate directory entries until an all-zero terminator.
    while pos * ENTRY_SIZE < slice.len() {
        let start = pos * ENTRY_SIZE;
        let block = &slice[start..start + ENTRY_SIZE];

        let original_first_thunk = read_u32(block, 0)?;
        let time_date_stamp     = read_u32(block, 4)?;
        let forwarder_chain     = read_u32(block, 8)?;
        let name                = read_u32(block, 12)?;
        let first_thunk         = read_u32(block, 16)?;

        // Terminator: all five fields zero.
        if original_first_thunk == 0
            && time_date_stamp     == 0
            && forwarder_chain     == 0
            && name                == 0
            && first_thunk         == 0
        {
            break;
        }

        entries.push(ImportEntry {
            original_first_thunk,
            time_date_stamp,
            forwarder_chain,
            name,
            first_thunk,
        });

        pos += 1;
    }

    Ok(entries)
}
