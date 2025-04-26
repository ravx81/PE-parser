use core::fmt;
use std::{error, io};
//use std::fmt::Formatter;

#[derive(Debug)]
pub enum Error{
    InvalidMagic(u16),
    UnsupportedOptionalHeader(u16),
    Io(std::io::Error),
}

impl fmt::Display for Error{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result{
        match self{
            Error::InvalidMagic(magic) => 
                write!(fmt, "Invalid magic number: 0x{magic:04X}"),
            Error::UnsupportedOptionalHeader(value) =>
                write!(fmt, "Unsupported optional-header magic value: 0x{value:04X}"),
            Error::Io(e) => 
                write!(fmt, "I/O error: {e}")
            }
        }
    }

impl core::error::Error for Error {}   

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self { Error::Io(err) }
}
    

pub type Result<T> = core::result::Result<T, Error>;
