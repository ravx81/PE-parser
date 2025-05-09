use core::fmt;

/// Custom error type for Parsey.
#[derive(Debug)]
pub enum Error {
    /// DOS header magic is wrong (expected `MZ` / 0x5A4D).
    InvalidMagic(u16),

    /// PE signature didn’t match `PE\0\0` (0x00004550).
    InvalidPeSignature(u32),

    /// Optional header magic wasn’t 0x10B (PE32) or 0x20B (PE32+).
    UnsupportedOptionalHeader(u16),

    /// An underlying I/O operation failed.
    Io(std::io::Error),

    /// A table’s RVA/offset fell outside the file data.
    InvalidTableOffset,

    /// Failed to read a null-terminated DLL name.
    InvalidDllName,

    /// Data in the buffer didn’t make sense.
    InvalidData,

    /// Buffer was smaller than we expected.
    InvalidSize { expected: usize, found: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidMagic(m) =>
                write!(f, "Bad DOS magic: 0x{m:04X}"),
            Error::InvalidPeSignature(s) =>
                write!(f, "Bad PE signature: 0x{s:08X}"),
            Error::UnsupportedOptionalHeader(m) =>
                write!(f, "Unknown optional-header magic: 0x{m:04X}"),
            Error::Io(e) =>
                write!(f, "I/O error: {e}"),
            Error::InvalidTableOffset =>
                write!(f, "Table offset is out of bounds"),
            Error::InvalidDllName =>
                write!(f, "Couldn’t read DLL name"),
            Error::InvalidData =>
                write!(f, "Malformed data in buffer"),
            Error::InvalidSize { expected, found } =>
                write!(f, "Expected at least {expected} bytes, found {found}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

/// Result type for PE parser operations.
pub type Result<T> = core::result::Result<T, Error>;
