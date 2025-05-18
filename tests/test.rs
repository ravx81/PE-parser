use std::path::Path;
use parsey::{PeFile, Parsed};

#[test]
fn parse_valid_pe() {
    let path = Path::new("tests/test.exe");
    let pe = PeFile::parse(path).expect("PE parsing failed");
    let parsed = Parsed::new(&pe);

    assert!(parsed.architecture().contains("x86") || parsed.architecture().contains("x64"));
}

#[test]
fn test_timestamp_and_subsystem() {
    let path = Path::new("tests/test.exe");
    let pe = PeFile::parse(path).unwrap();
    let parsed = Parsed::new(&pe);

    let timestamp = parsed.timestamp();
    let subsystem = parsed.subsystem();

    assert!(!timestamp.is_empty());
    assert!(subsystem.contains("Windows") || subsystem == "Unknown number");
}

#[test]
fn test_json_output() {
    let path = Path::new("tests/test.exe");
    let pe = PeFile::parse(path).unwrap();
    let parsed = Parsed::new(&pe);

    let pretty = serde_json::to_string_pretty(&parsed.pretty_json()).unwrap();
    let summary = serde_json::to_string_pretty(&parsed.summary_json()).unwrap();

    assert!(pretty.contains("sections"));
    assert!(summary.contains("entry_point"));
}

#[test]
fn test_sections_present() {
    let path = Path::new("tests/test.exe");
    let pe = PeFile::parse(path).unwrap();
    let parsed = Parsed::new(&pe);

    let sections = parsed.sections();
    assert!(!sections.is_empty());
    assert!(sections.iter().any(|s| s.name == ".text"));
}

#[test]
fn test_invalid_input() {
    use std::fs::File;
    use std::io::Write;

    // stworzenie tymczasowego pustego pliku
    let path = "tests/empty.exe";
    let _ = File::create(path).and_then(|mut f| f.write_all(b""));

    let result = PeFile::parse(Path::new(path));
    assert!(result.is_err());
}
