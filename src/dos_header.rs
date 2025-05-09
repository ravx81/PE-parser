use crate::headers::DosHeader;
use crate::errors::Result;
use std::ptr;

impl DosHeader {
    /// Read the DOS header (`IMAGE_DOS_HEADER`) from the start of `buffer`.
    ///
    /// # Safety
    ///
    /// This does an unaligned, direct memory read of the `#[repr(C)]` struct.
    /// The caller must guarantee that:
    /// - `buffer.len() >= std::mem::size_of::<DosHeader>()` (at least 64 bytes),  
    /// - `buffer` actually begins with a valid DOS header.
    ///
    /// In practice this is automatically satisfied by using
    /// [`PeFile::parse()`], which checks the magic and ensures `buffer`
    /// contains the full DOS header before calling this.
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        // SAFETY: see the `# Safety` section above
        let header = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const DosHeader) };
        Ok(header)
    }

    /// Convert the raw `e_lfanew` field into a `usize` offset.
    #[inline]
    pub fn e_lfanew(&self) -> usize {
        self.e_lfanew as usize
    }
}
