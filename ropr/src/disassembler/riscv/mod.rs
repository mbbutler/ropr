// use std::{fs::File, io::Write};

use crate::binary::{Bitness, Section};

use disc_v::{decode_inst_bytes, rv_isa};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

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

		let start_pc = (section.program_base() + section.section_vaddr()) as u64;
		let instructions: Vec<RVInstruction> = (0..bytes.len())
			.into_par_iter()
			.map(|i| {
				RVInstruction::new(
					decode_inst_bytes(isa, start_pc + i as u64, &bytes[i..]).unwrap_or_default(),
				)
			})
			.collect();

		// let instructions: Vec<RVInstruction> = DVDisassembler::new(
		// 	isa,
		// 	bytes,
		// 	(section.program_base() + section.section_vaddr()) as u64,
		// )
		// .map(RVInstruction::new)
		// .collect();

		// let mut file = File::create("rv_disassembly.txt").unwrap();
		// for rv_instr in &instructions {
		// 	file.write(format!("{:0>8x} {}\n", rv_instr.instr.pc, rv_instr).as_bytes())
		// 		.unwrap();
		// }

		Some(Disassembly {
			section,
			bytes,
			instructions,
			file_offset: section.program_base() + section.section_vaddr(),
		})
	}
}
