use crate::headers::{FileHeader, SectionHeader};
use std::ptr;
use crate::errors::Result;
impl SectionHeader{
     /// Parse all section headers declared in the COFF FileHeader.
    ///
    /// * `buffer` – complete PE image in memory.
    /// * `file_header` – already parsed COFF FileHeader containing
    ///   `number_of_sections` and `size_of_optional_header`.
    /// * `e_lfanew` – offset from DOS header to PE signature.
    ///
    /// Calculates the start of the section table as:
    /// `e_lfanew + 4 + size_of::<FileHeader>() + file_header.size_of_optional_header as usize`.
    /// Then allocates a Vec and reads each `SectionHeader` via `ptr::read_unaligned`.
    ///
    /// # Safety
    ///
    /// Uses unaligned, direct memory reads. Caller must ensure:
    /// - `buffer.len() >= section_offset + number_of_sections * size_of::<SectionHeader>()`
    /// - The bytes in that range are valid `SectionHeader` entries.
    pub fn parse_section_headers(buffer: &[u8], file_header: &FileHeader, e_lfanew: usize, ) -> Result<Vec<SectionHeader>>{
        //section_offset = e_lfanew + PE_signature... 
        let section_offset = e_lfanew + 4 + size_of::<crate::headers::FileHeader>() + file_header.size_of_optional_header as usize;
        let number_of_sections = file_header.number_of_sections as usize;
        let mut sections = Vec::with_capacity(number_of_sections);
    
        // first section_header stars here
        let base_ptr = unsafe { buffer.as_ptr().add(section_offset) as *const SectionHeader};
    
        for i in 0..number_of_sections{
            let ptr_section = unsafe {base_ptr.add(i)};
    
            let section = unsafe {ptr::read_unaligned(ptr_section)};
    
            sections.push(section);
        }
        Ok(sections)
    }
}
