use std::fs;
use std::convert::TryInto;
use crate::headers::{DosHeader, NtHeaders64, PE_SIGNATURE};

pub fn detect_architecture(path: &str) -> Result<String, String>{ 
    let buffer = fs::read(path).map_err(|e| format!("Error while reading file: {}", e))?;

    let e_lfanew = {
        let bytes: [u8; 4] = buffer[0x3C..0x40].try_into().unwrap();
        u32::from_le_bytes(bytes) as usize
    };

    let machine = {
        let b: [u8; 2] = buffer[e_lfanew+4..e_lfanew+6].try_into().unwrap();
        u16::from_le_bytes(b)
    };



    let arch = match machine {
        0x014c => "x86 (32‑bit)",
        0x8664 => "x64 (64‑bit)",
        0x1c0  => "ARM",
        0xaa64 => "ARM64",
        _      => "Nieznana architektura",
    };

    Ok(arch.to_string())
}
    

