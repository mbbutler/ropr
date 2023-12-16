use crate::binary::{Bitness, Section};

use disc_v::{rv_isa, Disassembler as DVDisassembler};

use self::rv_instruction::RVInstruction;

use super::Disassembly;
pub mod rv_instruction;

pub struct RVDisassembler {}

impl<'b> RVDisassembler {
	pub fn disassemble(section: &'b Section) -> Option<Disassembly<'b, RVInstruction>> {
		println!("Disassembling Section:");
		let bytes = section.bytes();

		if bytes.is_empty() {
			return None;
		}

		let isa = match section.bitness() {
			Bitness::Bits32 => rv_isa::rv32,
			Bitness::Bits64 => rv_isa::rv64,
		};

		// let disassembler = DVDisassembler::new(
		// 	isa,
		// 	bytes,
		// 	(section.program_base() + section.section_vaddr()) as u64,
		// );
		// let mut instrs = Vec::new();
		// for instr in disassembler {
		// 	if instr.len > 0 {
		// 		println!("{:?}", &decode_inst(isa, instr.pc, instr.inst));
		// 		instrs.push(instr);
		// 	}
		// }

		let instructions = DVDisassembler::new(
			isa,
			bytes,
			(section.program_base() + section.section_vaddr()) as u64,
		)
		.map(RVInstruction::new)
		.collect();

		// for instr in &instructions {
		// 	println!("{}", instr);
		// }

		Some(Disassembly {
			section,
			bytes,
			instructions,
			file_offset: section.program_base() + section.section_vaddr(),
		})
	}
}
