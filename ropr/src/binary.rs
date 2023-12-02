use crate::error::{Error, Result};
use disc_v::rv_isa;
use goblin::{elf64::program_header::PF_X, pe::section_table::IMAGE_SCN_MEM_EXECUTE, Object};
use std::{
	fs::read,
	path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy)]
pub enum Bitness {
	Bits32,
	Bits64,
}

pub struct Binary {
	path: PathBuf,
	bytes: Vec<u8>,
}

impl Binary {
	pub fn new(path: impl AsRef<Path>) -> Result<Self> {
		let path = path.as_ref();
		let bytes = read(path)?;
		let path = path.to_path_buf();
		Ok(Self { path, bytes })
	}

	pub fn path(&self) -> &Path {
		&self.path
	}

	pub fn sections(&self, raw: Option<bool>) -> Result<Vec<Section>> {
		match raw {
			Some(true) => Ok(vec![Section {
				file_offset: 0,
				section_vaddr: 0,
				program_base: 0,
				bytes: &self.bytes,
				rv_isa: rv_isa::rv64,
			}]),
			Some(false) => match Object::parse(&self.bytes)? {
				Object::Elf(e) => {
					let rv_isa = if e.is_64 { rv_isa::rv64 } else { rv_isa::rv32 };
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
								rv_isa,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				Object::PE(p) => {
					let rv_isa = if p.is_64 { rv_isa::rv64 } else { rv_isa::rv32 };
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
								rv_isa,
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
					let rv_isa = if e.is_64 { rv_isa::rv64 } else { rv_isa::rv32 };
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
								rv_isa,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				Object::PE(p) => {
					let rv_isa = if p.is_64 { rv_isa::rv64 } else { rv_isa::rv32 };
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
								rv_isa,
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
					rv_isa: rv_isa::rv32,
				}]),
			},
		}
	}
}

pub struct Section<'b> {
	file_offset: usize,
	section_vaddr: usize,
	program_base: usize,
	rv_isa: rv_isa,
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

	pub fn rv_isa(&self) -> rv_isa {
		self.rv_isa
	}

	pub fn bytes(&self) -> &[u8] {
		self.bytes
	}
}
