use pe_parser::export_table::parse_export_table;
use pe_parser::parser::PeFile;
use pe_parser::import_table::parse_import_table;
use pe_parser::Error;
use pe_parser::headers::{FileHeader, OptionalHeader32, OptionalHeader64, SectionHeader};

#[test]
fn test_file_header(){
    let path: &str = "tests/test.exe";
    let pe = PeFile::parse(path).expect("Failed");
} 
#[test]
fn test_optional_header(){
    let path: &str = "tests/test.exe";
    let pe = PeFile::parse(path).expect("Failed");
}
#[test]
fn test_errors(){
    let e1 = Error::InvalidMagic(4);
    println!("{e1}");
}
#[test]
fn test_section_headers(){
    let path: &str = "tests/test.exe";
    let pe = PeFile::parse(path).expect("Failed");
}
#[test]
fn test_import_table(){
    let path: &str = "tests/test.exe";
    let pe = PeFile::parse(path).expect("Failed");
    parse_import_table(&pe);
}
#[test]
fn test_export_table(){
    let path: &str = "tests/test.exe";
    let pe = PeFile::parse(path).expect("Failed");
    parse_export_table(&pe);
}