mod riscv;
mod rop_instruction;
mod x86;

use crate::{binary::Section, gadgets::GadgetIterator, rules::is_gadget_tail};
use riscv::RISCVDisassembler;
use rop_instruction::ROPInstruction;
use x86::X86Disassembler;

const MAX_INSTRUCTION_LENGTH: usize = 15;

pub enum Arch {
	X86_64,
	RISCV,
}

pub struct Disassembly<'b> {
	section: &'b Section<'b>,
	bytes: &'b [u8],
	instructions: Vec<ROPInstruction>,
	file_offset: usize,
}

impl<'b> Disassembly<'b> {
	pub fn new(section: &'b Section, arch: Arch) -> Option<Self> {
		let bytes = section.bytes();

		if bytes.is_empty() {
			return None;
		}

		let mut disassembler = match arch {
			Arch::X86_64 => X86Disassembler::new(section.bitness(), bytes),
			Arch::RISCV => RISCVDisassembler::new(section.bitness(), bytes),
		};

		// Fully disassemble program - cache for later use when finding gadgets
		let instructions: Vec<ROPInstruction> = (0..bytes.len())
			.map(|n| {
				disassembler.decode_at_offset(
					(section.program_base() + section.section_vaddr() + n) as u64,
					n,
				)
			})
			.collect();

		Some(Self {
			section,
			bytes,
			instructions,
			file_offset: section.program_base() + section.section_vaddr(),
		})
	}

	pub fn bytes(&self) -> &[u8] {
		self.bytes
	}

	pub fn file_offset(&self) -> usize {
		self.file_offset
	}

	pub fn instruction(&self, index: usize) -> Option<&ROPInstruction> {
		self.instructions.get(index)
	}

	pub fn is_tail_at(&self, index: usize, rop: bool, sys: bool, jop: bool, noisy: bool) -> bool {
		let instruction = self.instructions[index];
		is_gadget_tail(&instruction, rop, sys, jop, noisy)
	}

	pub fn gadgets_from_tail(
		&self,
		tail_index: usize,
		max_instructions: usize,
		noisy: bool,
		uniq: bool,
	) -> GadgetIterator {
		assert!(max_instructions > 0);
		let start_index =
			tail_index.saturating_sub((max_instructions - 1) * MAX_INSTRUCTION_LENGTH);
		let predecessors = &self.instructions[start_index..tail_index];
		let tail_instruction = self.instructions[tail_index];
		GadgetIterator::new(
			self.section.program_base() + self.section.section_vaddr(),
			tail_instruction,
			predecessors,
			max_instructions,
			noisy,
			uniq,
			start_index,
		)
	}
}

pub trait ROPDisassembler {
	fn decode_at_offset(&mut self, ip: u64, offset: usize) -> ROPInstruction;
}
