use crate::export_table::parse_export_table;
use crate::export_table::ExportEntry;
use crate::import_table::ImportEntry;
use crate::import_table::parse_import_table;
use crate::parser::PeFile;
use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{UNIX_EPOCH, Duration};
use std::path::Path;
use serde::Serialize;
use crate::utils::{read_u16, format_as_hex};

#[derive(Serialize)]
/// Wrapper around a parsed PE file, exposing higher-level helper methods.
/// This allows transforming raw PE data into human-friendly representations.
pub struct Parsed<'a> {
    raw: &'a PeFile,
}

#[derive(Serialize)]
/// Describes a parsed section in a PE file with display-friendly fields.
pub struct ParsedSection {
    pub name: String,
    pub virtual_size: String,
    pub virtual_address: String,
    pub size_of_raw_data: String,
    pub pointer_to_raw_data: String,
    pub pointer_to_relocations: String,
    pub pointer_to_linenumbers: String,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: String,
    pub flags: Vec<&'static str>,
}

#[derive(Serialize)]
/// Contains a full view of PE file metadata in a structured, readable format.
pub struct ParsedPretty {
    pub architecture: String,
    pub entry_point: String,
    pub image_base: String,
    pub timestamp: String,
    pub subsystem: String,
    pub dll_characteristics: Vec<String>,
    pub sections: Vec<ParsedSection>,
    pub import_table: Option<Vec<ImportEntry>>,
    pub export_table: Option<Vec<ExportEntry>>,
}

#[derive(Serialize)]
/// A lightweight summary of a PE file with core identifying details.
pub struct ParsedSummary {
    pub architecture: String,
    pub entry_point: String,
    pub image_base: String,
    pub timestamp: String,
    pub subsystem: String,
}

impl<'a> Parsed<'a> {
    /// Creates a new parsed wrapper instance from a raw PE file reference.
    ///
    /// This enables access to structured views like `pretty_json()` or `summary_json()`.
    pub fn new(raw: &'a PeFile) -> Self {
        Parsed { raw }
    }

    /// Builds a detailed, pretty-printed representation of the PE file.
    ///
    /// Includes architecture, section info, entry point, characteristics,
    /// and optionally parsed import/export tables. Designed for human inspection.
    pub fn pretty_json(&self) -> ParsedPretty {
        ParsedPretty {
            architecture: self.architecture().to_string(),
            entry_point: self.entry_point(),
            image_base: self.image_base(),
            timestamp: self.timestamp(),
            subsystem: self.subsystem().to_string(),
            dll_characteristics: self
                .dll_characteristics()
                .iter()
                .map(|(_, s)| s.to_string())
                .collect(),
            sections: self.sections(),
            import_table: parse_import_table(self.raw).ok(),
            export_table: parse_export_table(self.raw).ok(),
        }
    }

    /// Returns a compact summary of key PE fields.
    ///
    /// Intended for overview displays, such as CLI tools or file scanners.
    pub fn summary_json(&self) -> ParsedSummary {
        ParsedSummary {
            architecture: self.architecture().to_string(),
            entry_point: self.entry_point(),
            image_base: self.image_base(),
            timestamp: self.timestamp(),
            subsystem: self.subsystem().to_string(),
        }
    }

    /// Returns the program entry point address in hexadecimal.
    ///
    /// This is where execution begins when the program loads.
    /// The address is taken from the Optional Header.
    pub fn entry_point(&self) -> String {
        format!("0x{:X}", self.raw.optional_header.address_of_entry_point())
    }

    /// Returns the image base address as a hexadecimal string.
    ///
    /// This is the preferred virtual memory address where the image is loaded.
    /// It varies between PE32 and PE32+ formats.
    pub fn image_base(&self) -> String {
        format!("0x{:X}", self.raw.optional_header.image_base())
    }

    /// Returns the subsystem type as a readable string.
    ///
    /// Indicates the intended environment for the PE file (GUI, console, etc).
    /// Falls back to "Unknown number" if not recognized.
    pub fn subsystem(&self) -> &str {
        match self.raw.optional_header.subsystem() {
            2 => "Windows GUI (2)",
            3 => "Windows Console (3)",
            9 => "Windows CE GUI (9)",
            _ => "Unknown number",
        }
    }

    /// Returns a list of DLL characteristic flags and their descriptions.
    ///
    /// Flags are extracted from the Optional Header and filtered from known masks.
    /// Provides insight into binary security features like ASLR, DEP, etc.
    pub fn dll_characteristics(&self) -> Vec<(u64, &str)> {
        let flag = self.raw.optional_header.dll_characteristics();
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

        flag_descriptions
            .iter()
            .filter(|(mask, _)| flag & mask != 0)
            .map(|(mask, desc)| (*mask, *desc))
            .collect()
    }

    /// Identifies the PE machine architecture (e.g., x86, x64).
    ///
    /// Reads the machine type directly from the PE header.
    /// Returns a string suitable for display in diagnostics or metadata.
    pub fn architecture(&self) -> &'static str {
        let machine_offset = self.raw.e_lfanew + 4;

        let raw_arch = match read_u16(&self.raw.buffer, machine_offset) {
            Ok(value) => value,
            Err(_) => return "Unknown architecture",
        };

        match raw_arch {
            0x014c => "x86 (32‑bit)",
            0x8664 => "x64 (64‑bit)",
            0x1c0 => "ARM",
            0xaa64 => "ARM64",
            _ => "Unknown architecture",
        }
    }

    /// Converts the PE timestamp to a formatted UTC datetime string.
    ///
    /// The timestamp comes from the FileHeader and represents the linker time.
    /// Useful for version comparison and forensic analysis.
    pub fn timestamp(&self) -> String {
        let d = UNIX_EPOCH + Duration::from_secs(self.raw.file_header.time_date_stamp as u64);
        DateTime::<Utc>::from(d).format("%Y-%m-%d %H:%M:%S").to_string()
    }

    /// Returns the linker version in `vX.Y` format.
    pub fn linker_version(&self) -> String {
        let oh = &self.raw.optional_header;
        format!("Linker v{}.{}", oh.major_linker_version(), oh.minor_linker_version())
    }

    /// Returns the target OS version as a string.
    pub fn os_version(&self) -> String {
        let oh = &self.raw.optional_header;
        format!("OS v{}.{}", oh.major_os_version(), oh.minor_os_version())
    }

    /// Returns the declared image version string.
    pub fn image_version(&self) -> String {
        let oh = &self.raw.optional_header;
        format!("Image v{}.{}", oh.major_image_version(), oh.minor_image_version())
    }

    /// Returns the declared subsystem version string.
    pub fn subsystem_version(&self) -> String {
        let oh = &self.raw.optional_header;
        format!("Subsystem v{}.{}", oh.major_subsystem_version(), oh.minor_subsystem_version())
    }

    /// Extracts the COFF FileHeader flags and their meanings.
    ///
    /// Flags describe attributes of the file (executable, stripped debug, etc).
    /// Filtered from a fixed known list.
    pub fn characteristics(&self) -> Vec<(u16, &'static str)> {
        let flag = self.raw.file_header.characteristics;
        let file_header_flags = [
            (0x0001, "RELOCS_STRIPPED"),
            (0x0002, "EXECUTABLE_IMAGE"),
            (0x0004, "LINE_NUMS_STRIPPED (deprecated)"),
            (0x0008, "LOCAL_SYMS_STRIPPED (deprecated)"),
            (0x0010, "AGGRESSIVE_WS_TRIM (obsolete)"),
            (0x0020, "LARGE_ADDRESS_AWARE"),
            (0x0040, "RESERVED"),
            (0x0080, "BYTES_REVERSED_LO (deprecated)"),
            (0x0100, "32BIT_MACHINE"),
            (0x0200, "DEBUG_STRIPPED"),
            (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
            (0x0800, "NET_RUN_FROM_SWAP"),
            (0x1000, "SYSTEM"),
            (0x2000, "DLL"),
            (0x4000, "UP_SYSTEM_ONLY"),
            (0x8000, "BYTES_REVERSED_HI (deprecated)"),
        ];

        file_header_flags
            .iter()
            .filter(|(mask, _)| flag & mask != 0)
            .map(|(mask, desc)| (*mask, *desc))
            .collect()
    }

    /// Determines file type (EXE, DLL, etc.) based on file extension.
    ///
    /// This is a best-effort heuristic based on common PE suffixes.
    pub fn detect_type(path: &Path) -> Option<String> {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|ext| match ext {
                "exe" => "Executable (EXE)".into(),
                "dll" => "Dynamic-Link Library (DLL)".into(),
                "sys" => "System Driver (SYS)".into(),
                "ocx" => "ActiveX Control (OCX)".into(),
                "scr" => "Screensaver (SCR)".into(),
                "cpl" => "Control Panel Applet (CPL)".into(),
                "efi" => "UEFI Application (EFI)".into(),
                other => other.to_string(),
            })
    }

    /// Converts section flags to readable labels (e.g., CODE, WRITE).
    ///
    /// Based on Microsoft's documented bitfields. Used to decode `.text`, `.data`, etc.
    fn parse_section_flags(&self, flags: &u32) -> Vec<&'static str> {
        let flag_defs = [
            (0x00000008, "NO_PAD"),
            (0x00000020, "CODE"),
            (0x00000040, "INITIALIZED_DATA"),
            (0x00000080, "UNINITIALIZED_DATA"),
            (0x00000100, "LNK_OTHER"),
            (0x00000200, "LNK_INFO"),
            (0x00000800, "LNK_REMOVE"),
            (0x00001000, "LNK_COMDAT"),
            (0x00004000, "NO_DEFER_SPEC_EXC"),
            (0x00008000, "GPREL"),
            (0x01000000, "LNK_NRELOC_OVFL"),
            (0x02000000, "DISCARDABLE"),
            (0x04000000, "NOT_CACHED"),
            (0x08000000, "NOT_PAGED"),
            (0x10000000, "SHARED"),
            (0x20000000, "EXECUTE"),
            (0x40000000, "READ"),
            (0x80000000, "WRITE"),
            (0x00100000, "ALIGN_1BYTES"),
            (0x00200000, "ALIGN_2BYTES"),
            (0x00300000, "ALIGN_4BYTES"),
            (0x00400000, "ALIGN_8BYTES"),
            (0x00500000, "ALIGN_16BYTES"),
            (0x00600000, "ALIGN_32BYTES"),
            (0x00700000, "ALIGN_64BYTES"),
            (0x00800000, "ALIGN_128BYTES"),
            (0x00900000, "ALIGN_256BYTES"),
            (0x00A00000, "ALIGN_512BYTES"),
            (0x00B00000, "ALIGN_1024BYTES"),
            (0x00C00000, "ALIGN_2048BYTES"),
            (0x00D00000, "ALIGN_4096BYTES"),
            (0x00E00000, "ALIGN_8192BYTES"),
        ];

        flag_defs
            .iter()
            .filter(|(mask, _)| flags & mask != 0)
            .map(|(_, desc)| *desc)
            .collect()
    }

    /// Parses section headers and transforms them into structured, readable output.
    ///
    /// Converts sizes and addresses into hex strings, and decodes section flags.
    /// Intended for visualization in tools or APIs.
    pub fn sections(&self) -> Vec<ParsedSection> {
        self.raw
            .sections
            .iter()
            .map(|section| {
                let name = std::str::from_utf8(&section.name)
                    .unwrap_or("Can't read section name")
                    .trim_end_matches('\0')
                    .to_string();

                ParsedSection {
                    name,
                    virtual_size: format_as_hex(section.virtual_size),
                    virtual_address: format_as_hex(section.virtual_address),
                    size_of_raw_data: format_as_hex(section.size_of_raw_data),
                    pointer_to_raw_data: format_as_hex(section.pointer_to_raw_data),
                    pointer_to_relocations: format_as_hex(section.pointer_to_relocations),
                    pointer_to_linenumbers: format_as_hex(section.pointer_to_linenumbers),
                    number_of_relocations: section.number_of_relocations,
                    number_of_linenumbers: section.number_of_linenumbers,
                    characteristics: format_as_hex(section.characteristics),
                    flags: self.parse_section_flags(&section.characteristics),
                }
            })
            .collect()
    }
}
