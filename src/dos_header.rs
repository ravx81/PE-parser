use crate::headers::{PE_SIGNATURE, DosHeader};
use crate::errors::{Error, Result};
use std::ptr;
impl DosHeader{
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        // Odczytujemy całą strukturę
        let header = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const DosHeader) };
        if header.e_magic != 0x5A4D {
            return Err(Error::InvalidMagic(header.e_magic));
        }
        Ok(header)
    }

    #[inline]
    pub fn e_lfanew(&self) -> usize {
        self.e_lfanew as usize
    }
}