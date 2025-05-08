use std::path::Path;

use pe_parser::export_table::parse_export_table;
use pe_parser::parser::PeFile;
use pe_parser::import_table::parse_import_table;
use pe_parser::{section_header, Error};
use pe_parser::headers::{FileHeader, OptionalHeader32, OptionalHeader64, SectionHeader};
use pe_parser::view::Parsed;

#[test]
fn test_os_version(){
    let path = Path::new("D:\\test");
    let pe = PeFile::parse(path).expect("Failed");
}
#[test]
fn parse_section_header(){
    let path = Path::new("tests/test.exe");
    let pe = PeFile::parse(path).expect("Failed");
    pe.parsed().sections();
}
#[test]
fn test_json(){
    let path = Path::new("tests/test.exe");
    let pe = PeFile::parse(path).expect("Failed");
    let raw     = serde_json::to_string_pretty(&pe.raw()).unwrap();
    let pretty  = serde_json::to_string_pretty(&pe.parsed().pretty_json()).unwrap();
    let summary = serde_json::to_string_pretty(&pe.parsed().summary_json()).unwrap();

    println!("{}", pretty);
}