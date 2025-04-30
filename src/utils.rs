use crate::parser::PeFile;


pub fn rva_to_offset(pe: &PeFile, rva: u32) -> Option<usize> {

        for section in pe.parse_section_headers(){
            //check if rva is in a section
            if rva > section.virtual_address && rva < section.virtual_address + section.virtual_size{
                //difference e.g 0x2100 - 0x2000 it gives how many bytes we should move on in memory
                let memory_delta = rva - section.virtual_address;
                // section_start + how many bytes we should move
                return Some(section.pointer_to_raw_data as usize + memory_delta as usize);
            }
        }
        None
    }