

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32, // RVA do danych (czyli offset w pamięci po załadowaniu)
    pub size: u32,            // rozmiar danych
}

pub const PE_SIGNATURE: u32 = 0x00004550;


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    pub e_magic:   u16,
    pub e_cblp:    u16,
    pub e_cp:      u16,
    pub e_crlc:    u16,
    pub e_cparhdr: u16,
    pub e_minalloc:u16,
    pub e_maxalloc:u16,
    pub e_ss:      u16,
    pub e_sp:      u16,
    pub e_csum:    u16,
    pub e_ip:      u16,
    pub e_cs:      u16,
    pub e_lfarlc:  u16,
    pub e_ovno:    u16,
    pub e_res:     [u16; 4],
    pub e_oemid:   u16,
    pub e_oeminfo: u16,
    pub e_res2:    [u16; 10],
    pub e_lfanew:  u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileHeader {
    pub machine:              u16,
    pub number_of_sections:   u16,
    pub time_date_stamp:      u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols:    u32,
    pub size_of_optional_header: u16,
    pub characteristics:      u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader32 {
    pub magic:                    u16,
    pub major_linker_version:     u8,
    pub minor_linker_version:     u8,
    pub size_of_code:             u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point:   u32,
    pub base_of_code:             u32,
    pub base_of_data:             u32,
    pub image_base:               u32,
    pub section_alignment:        u32,
    pub file_alignment:           u32,
    pub major_os_version:         u16,
    pub minor_os_version:         u16,
    pub major_image_version:      u16,
    pub minor_image_version:      u16,
    pub major_subsystem_version:  u16,
    pub minor_subsystem_version:  u16,
    pub win32_version_value:      u32,
    pub size_of_image:            u32,
    pub size_of_headers:          u32,
    pub checksum:                 u32,
    pub subsystem:                u16,
    pub dll_characteristics:      u16,
    pub size_of_stack_reserve:    u32,
    pub size_of_stack_commit:     u32,
    pub size_of_heap_reserve:     u32,
    pub size_of_heap_commit:      u32,
    pub loader_flags:             u32,
    pub number_of_rva_and_sizes:  u32,
    pub data_directory:           [DataDirectory; 16],
}

/// Optional Header for PE32+ (fields as u64 where appropriate)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader64 {
    pub magic:                    u16,
    pub major_linker_version:     u8,
    pub minor_linker_version:     u8,
    pub size_of_code:             u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point:   u32,
    pub base_of_code:             u32,
    // base_of_data is absent in PE32+
    pub image_base:               u64,
    pub section_alignment:        u32,
    pub file_alignment:           u32,
    pub major_os_version:         u16,
    pub minor_os_version:         u16,
    pub major_image_version:      u16,
    pub minor_image_version:      u16,
    pub major_subsystem_version:  u16,
    pub minor_subsystem_version:  u16,
    pub win32_version_value:      u32,
    pub size_of_image:            u32,
    pub size_of_headers:          u32,
    pub checksum:                 u32,
    pub subsystem:                u16,
    pub dll_characteristics:      u16,
    pub size_of_stack_reserve:    u64,
    pub size_of_stack_commit:     u64,
    pub size_of_heap_reserve:     u64,
    pub size_of_heap_commit:      u64,
    pub loader_flags:             u32,
    pub number_of_rva_and_sizes:  u32,
    pub data_directory:           [DataDirectory; 16],
}

/// Unified enum for optional header
pub enum OptionalHeader {
    Header32(OptionalHeader32),
    Header64(OptionalHeader64),
}

/// Macro to generate u64-returning accessor methods for common fields
macro_rules! impl_optional_header {
    ($enum:ident { $($field:ident),* $(,)? }) => {
        impl $enum {
            $(
                pub fn $field(&self) -> u64 {
                    match self {
                        $enum::Header32(h) => h.$field as u64,
                        $enum::Header64(h) => h.$field as u64,
                    }
                }
            )*
        }
    };
}

// Generate accessors for fields present in both variants
impl_optional_header!(OptionalHeader {
    magic,
    major_linker_version,
    minor_linker_version,
    size_of_code,
    size_of_initialized_data,
    size_of_uninitialized_data,
    address_of_entry_point,
    base_of_code,
    image_base,
    section_alignment,
    file_alignment,
    major_os_version,
    minor_os_version,
    major_image_version,
    minor_image_version,
    major_subsystem_version,
    minor_subsystem_version,
    win32_version_value,
    size_of_image,
    size_of_headers,
    checksum,
    subsystem,
    dll_characteristics,
    size_of_stack_reserve,
    size_of_stack_commit,
    size_of_heap_reserve,
    size_of_heap_commit,
    loader_flags,
    number_of_rva_and_sizes,
});

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NtHeaders32 {
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NtHeaders64 {
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],             
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}


