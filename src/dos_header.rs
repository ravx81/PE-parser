use crate::headers::DosHeader;
use crate::errors::{Error, Result};
use std::ptr;
impl DosHeader{
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        let header = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const DosHeader) };
        Ok(header)
    }

    #[inline]
    pub fn e_lfanew(&self) -> usize {
        self.e_lfanew as usize
    }
}