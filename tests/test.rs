use pe_parser::parser::detect_architecture;


#[test]
fn detect_x64(){
    let path = "tests/test.exe";
    let arch = detect_architecture(path).expect("Should return x64");
    assert_eq!(arch, "x64 (64‑bit)");
}

#[test]
fn detect_x32(){
    let path = "tests/7z2409.exe";
    let arch = detect_architecture(path).expect("Should return x86");
    assert_eq!(arch, "x86 (32‑bit)");
}
#[test]
fn detect_arm64(){
    let path: &str = "tests/7z2409-arm64.exe";
    let arch  = detect_architecture(path).expect("Should return ARM64");
    assert_eq!(arch, "ARM64");
}