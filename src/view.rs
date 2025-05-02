use crate::parser::PeFile;
use chrono::prelude::DateTime;
use chrono::Utc;
pub fn subsystem(&pe: PeFile) -> &str { 
    let number = self.optional_header.subsystem();
    let result = match number{
        2 => "Windows GUI (2)",
        3 => "Windows Console (3)",
        9 => "Windows CE GUI (9)",
        _ => "Unknown number",
    };
    result
}
pub fn dll_characteristics(&pe) -> Vec<(u16, &'static str)> { 
    let flag = self.optional_header.dll_characteristics();
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
    let machine_offset = self.e_lfanew + 4;
    let raw_arch = u16::from_le_bytes(self.buffer[machine_offset..machine_offset+2 ].try_into().expect("machine field out of bounds"));

    match raw_arch {
        0x014c => "x86 (32‑bit)",
        0x8664 => "x64 (64‑bit)",
        0x1c0  => "ARM",
        0xaa64 => "ARM64",
        _      => "Unknowed architecture",
    }
}

pub fn timestamp(&self) -> String {
    let d = UNIX_EPOCH + Duration::from_secs(self.file_header.time_date_stamp as u64);
    let datetime = DateTime::<Utc>::from(d);
    let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    timestamp_str
}