Parsey — Usage Guide

Welcome! This is a short and practical guide on how to use `parsey_core` to inspect PE files like `.exe`, `.dll`, `.sys`, etc. You can either go deep with low-level access or just grab what you need with a friendly high-level API. Your choice.

## Getting started

Start by parsing a file:

```rust
use parsey_core::{PeFile, Parsed};
use std::path::Path;

let path = Path::new("your_file.exe");
let pe = PeFile::parse(path)?;

I offer you two API, raw and friendly.
You can use the raw API like this:

let entry = pe.raw().optional_header.architecture();
let base = pe.raw().optional_header.image_base();
let sections = &pe.raw().sections;

Or go for the friendly API instead:
let entry = pe.parsed().architecture();
let base = pe.parsed().image_base();
let sections = &pe.parsed().sections;


Here I made a list of all friendly fields that I parsed for you:
architecture()
characteristics()
dll_characteristics()
entry_point()
image_base()
image_version()
linker_version()
os_version()
pretty_json()
sections()
subsystem()
subsystem_version()
summary_json()
timestamp()

Enjoy using library!

