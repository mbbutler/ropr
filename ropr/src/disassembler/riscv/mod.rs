use crate::binary::{Bitness, Section};

use disc_v::{rv_isa, Disassembler as DVDisassembler};

use self::rv_instruction::RVInstruction;

use super::Disassembly;
pub mod rv_instruction;

pub struct RVDisassembler {}

impl<'b> RVDisassembler {
	pub fn disassemble(section: &'b Section) -> Option<Disassembly<'b, RVInstruction>> {
		let bytes = section.bytes();

		if bytes.is_empty() {
			return None;
		}

		let isa = match section.bitness() {
			Bitness::Bits32 => rv_isa::rv32,
			Bitness::Bits64 => rv_isa::rv64,
		};

		let instructions = DVDisassembler::new(
			isa,
			bytes,
			(section.program_base() + section.section_vaddr()) as u64,
		)
		.map(RVInstruction::new)
		.collect();

		Some(Disassembly {
			section,
			bytes,
			instructions,
			file_offset: section.program_base() + section.section_vaddr(),
		})
	}
}
