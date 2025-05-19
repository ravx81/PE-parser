# Parsey

**Parsey** is a lightweight Rust library for reading and analyzing Portable Executable (PE) files — like `.exe`, `.dll`, `.sys`, and more.

---

## Features

- ✅ Parses full PE structure (DOS, COFF, Optional headers)
- 🔍 Supports both 32-bit (PE32) and 64-bit (PE32+) formats
- 📥 Reads import/export tables
- 📦 Provides clean and friendly API (`Parsed`)
- 🔧 Zero dependencies on OS APIs — pure buffer parsing

---

## Usage

Add to your project:

```toml
[dependencies]
parsey = { git = "https://github.com/ravx81/Parsey" }
