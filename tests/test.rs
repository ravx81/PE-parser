use std::path::Path;

use pe_parser::export_table::parse_export_table;
use pe_parser::parser::PeFile;
use pe_parser::import_table::parse_import_table;
use pe_parser::{section_header, Error};
use pe_parser::headers::{FileHeader, OptionalHeader32, OptionalHeader64, SectionHeader};

#[test]
fn test_os_version(){
    let path = Path::new("D:\\test");
    let pe = PeFile::parse(path).expect("Failed");
    pe.parsed().detect_type(path);
}
#[test]
fn parse_section_header(){
    let path = Path::new("tests/test.exe");
    let pe = PeFile::parse(path).expect("Failed");
    pe.parsed().sections();
}