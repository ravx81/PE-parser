use crate::{headers::{FileHeader, SectionHeader}};
use std::{fs::File, ptr};
use crate::errors::Result;
impl SectionHeader{
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
