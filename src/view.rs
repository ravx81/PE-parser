use crate::parser::PeFile;
use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{UNIX_EPOCH, Duration};

pub struct Parsed<'a> {
    raw: &'a PeFile,
}

impl<'a> Parsed<'a> {
    pub fn new(raw: &'a PeFile) -> Self {
        Parsed {raw}
    }

    pub fn entry_point(&self) -> String{
        format!("0x{:X}", self.raw.optional_header.address_of_entry_point())
    }
    pub fn image_base(&self) -> String{
        format!("0x{:X}", self.raw.optional_header.image_base())
    }

    pub fn subsystem(&self) -> &str { 
        let number = self.raw.optional_header.subsystem();
        let result = match number{
            2 => "Windows GUI (2)",
            3 => "Windows Console (3)",
            9 => "Windows CE GUI (9)",
            _ => "Unknown number",
        };
        result
    }
    pub fn dll_characteristics(&self) -> Vec<(u64, &str)> { 
        let flag = self.raw.optional_header.dll_characteristics();
        let mut results = Vec::new();
        let flag_descriptions = [
            (0x0020, "HIGH_ENTROPY_VA"),
            (0x0040, "DYNAMIC_BASE (ASLR)"),
            (0x0080, "FORCE_INTEGRITY"),
            (0x0100, "NX_COMPAT (DEP)"),
            (0x0200, "NO_ISOLATION"),
            (0x0400, "NO_SEH"),
            (0x0800, "NO_BIND"),
            (0x1000, "APPCONTAINER"),
            (0x2000, "WDM_DRIVER"),
            (0x4000, "GUARD_CF"),
            (0x8000, "TERMINAL_SERVER_AWARE"),
            ];
        for (mask, description) in &flag_descriptions{
            if flag & mask != 0{
                results.push((*mask, *description));
            }
        }
        results
    }
    
    pub fn architecture(&self) -> &'static str {
        let machine_offset = self.raw.e_lfanew + 4;
        let raw_arch = u16::from_le_bytes(self.raw.buffer[machine_offset..machine_offset+2 ].try_into().expect("machine field out of bounds"));
    
        match raw_arch {
            0x014c => "x86 (32‑bit)",
            0x8664 => "x64 (64‑bit)",
            0x1c0  => "ARM",
            0xaa64 => "ARM64",
            _      => "Unknowed architecture",
        }
    }
    
    pub fn timestamp(&self) -> String {
        let d = UNIX_EPOCH + Duration::from_secs(self.raw.file_header.time_date_stamp as u64);
        let datetime = DateTime::<Utc>::from(d);
        let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
        timestamp_str
    }

    pub fn linker_version(&self) -> String {
        let oh = &self.raw.optional_header;
        format!("Linker v{}.{}", oh.major_linker_version(), oh.minor_linker_version())
    }

    pub fn os_version(&self) -> String {
        let oh = &self.raw.optional_header;
        format!("OS v{}.{}", oh.major_os_version(), oh.minor_os_version())
    }

    pub fn image_version(&self) -> String {
        let oh = &self.raw.optional_header;
        format!("Image v{}.{}", oh.major_image_version(), oh.minor_image_version())
    }

    pub fn subsystem_version(&self) -> String {
        let oh = &self.raw.optional_header;
        format!("Subsystem v{}.{}", oh.major_subsystem_version(), oh.minor_subsystem_version())
    }
}

