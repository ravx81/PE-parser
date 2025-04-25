use pe_parser::parser::PeFile;


#[test]
fn detect_x64(){
    let path = "tests/test.exe";
    let pe = PeFile::parse(path).expect("failed to parse x64");
    assert_eq!(pe.architecture(), "x64 (64‑bit)");
}

#[test]
fn detect_x32(){
    let path = "tests/7z2409.exe";
    let pe = PeFile::parse(path).expect("failed to parse x32");
    assert_eq!(pe.architecture(), "x86 (32‑bit)");
}
#[test]
fn detect_arm64(){
    let path: &str = "tests/7z2409-arm64.exe";
    let pe = PeFile::parse(path).expect("failed to parse ARM64");
    assert_eq!(pe.architecture(), "ARM64");
}
#[test]
fn test_file_header(){
    let path: &str = "tests/test.exe";
    let pe = PeFile::parse(path).expect("Failed");
    pe.print_file_header();
} 
#[test]
fn test_optional_header(){
    let path: &str = "tests/test.exe";
    let pe = PeFile::parse(path).expect("Failed");
    pe.print_optional_header();
}
