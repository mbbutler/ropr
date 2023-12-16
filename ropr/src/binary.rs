use crate::error::{Error, Result};
use goblin::{elf64::program_header::PF_X, pe::section_table::IMAGE_SCN_MEM_EXECUTE, Object};
use std::{
	fmt::Display,
	fs::read,
	path::{Path, PathBuf},
};

const ELF_X86: u16 = 0x03;
const ELF_X64: u16 = 0x3e;
const ELF_RISCV: u16 = 0xf3;

#[derive(Debug, Clone, Copy)]
pub enum Arch {
	RiscV,
	X86,
}

#[derive(Debug, Clone, Copy)]
pub enum Bitness {
	Bits32,
	Bits64,
}

pub struct Binary {
	path: PathBuf,
	bytes: Vec<u8>,
	arch: Arch,
}

impl Binary {
	pub fn new(path: impl AsRef<Path>) -> Result<Self> {
		let path = path.as_ref();
		let bytes = read(path)?;
		let path = path.to_path_buf();
		let object = Object::parse(&bytes)?;
		let arch = match object {
			Object::Elf(e) => match e.header.e_machine {
				ELF_RISCV => Arch::RiscV,
				ELF_X86 | ELF_X64 => Arch::X86,
				_ => Arch::X86,
			},
			_ => Arch::X86,
		};
		Ok(Self { path, bytes, arch })
	}

	pub fn path(&self) -> &Path {
		&self.path
	}

	pub fn arch(&self) -> &Arch {
		&self.arch
	}

	pub fn sections(&self, raw: Option<bool>) -> Result<Vec<Section>> {
		println!("Parsing sections...");
		match raw {
			Some(true) => Ok(vec![Section {
				file_offset: 0,
				section_vaddr: 0,
				program_base: 0,
				bytes: &self.bytes,
				bitness: Bitness::Bits64,
			}]),
			Some(false) => match Object::parse(&self.bytes)? {
				Object::Elf(e) => {
					let bitness = if e.is_64 {
						Bitness::Bits64
					} else {
						Bitness::Bits32
					};
					let sections = e
						.program_headers
						.iter()
						.filter(|header| header.p_flags & PF_X != 0)
						.map(|header| {
							let start_offset = header.p_offset as usize;
							let end_offset = start_offset + header.p_filesz as usize;
							Section {
								file_offset: start_offset,
								section_vaddr: header.p_vaddr as usize,
								program_base: 0,
								bytes: &self.bytes[start_offset..end_offset],
								bitness,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				Object::PE(p) => {
					let bitness = if p.is_64 {
						Bitness::Bits64
					} else {
						Bitness::Bits32
					};
					let sections = p
						.sections
						.iter()
						.filter(|section| (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
						.map(|section| {
							let start_offset = section.pointer_to_raw_data as usize;
							let end_offset = start_offset + section.size_of_raw_data as usize;
							Section {
								file_offset: start_offset,
								section_vaddr: section.virtual_address as usize,
								program_base: p.image_base,
								bytes: &self.bytes[start_offset..end_offset],
								bitness,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				Object::Unknown(_) => Err(Error::ParseErr),
				_ => Err(Error::Unsupported),
			},
			// Default behaviour - fall back to raw if able
			None => match Object::parse(&self.bytes)? {
				Object::Elf(e) => {
					println!("Image is an ELF");
					let bitness = if e.is_64 {
						Bitness::Bits64
					} else {
						Bitness::Bits32
					};
					println!("Bitness = {:?}", bitness);
					let sections = e
						.program_headers
						.iter()
						.filter(|header| header.p_flags & PF_X != 0)
						.map(|header| {
							let start_offset = header.p_offset as usize;
							let end_offset = start_offset + header.p_filesz as usize;
							Section {
								file_offset: start_offset,
								section_vaddr: header.p_vaddr as usize,
								program_base: 0,
								bytes: &self.bytes[start_offset..end_offset],
								bitness,
							}
						})
						.collect::<Vec<_>>();
					println!("Number of executable sections = {}", sections.len());
					Ok(sections)
				}
				Object::PE(p) => {
					let bitness = if p.is_64 {
						Bitness::Bits64
					} else {
						Bitness::Bits32
					};
					let sections = p
						.sections
						.iter()
						.filter(|section| (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
						.map(|section| {
							let start_offset = section.pointer_to_raw_data as usize;
							let end_offset = start_offset + section.size_of_raw_data as usize;
							Section {
								file_offset: start_offset,
								section_vaddr: section.virtual_address as usize,
								program_base: p.image_base,
								bytes: &self.bytes[start_offset..end_offset],
								bitness,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				_ => Ok(vec![Section {
					file_offset: 0,
					section_vaddr: 0,
					program_base: 0,
					bytes: &self.bytes,
					bitness: Bitness::Bits32,
				}]),
			},
		}
	}
}

impl Display for Binary {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "{:?}", self.path)?;
		write!(f, "{:?}", self.arch)
	}
}

pub struct Section<'b> {
	file_offset: usize,
	section_vaddr: usize,
	program_base: usize,
	bitness: Bitness,
	bytes: &'b [u8],
}

impl Section<'_> {
	pub fn file_offset(&self) -> usize {
		self.file_offset
	}

	pub fn section_vaddr(&self) -> usize {
		self.section_vaddr
	}

	pub fn program_base(&self) -> usize {
		self.program_base
	}

	pub fn bitness(&self) -> Bitness {
		self.bitness
	}

	pub fn bytes(&self) -> &[u8] {
		self.bytes
	}
}

impl Display for Section<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "Offset: {}", self.file_offset)?;
		writeln!(f, "VAddr: {}", self.section_vaddr)?;
		writeln!(f, "Program Base: {}", self.program_base)?;
		writeln!(f, "Size: {}", self.bytes.len())?;
		write!(f, "Bitness: {:?}", self.bitness)
	}
}
