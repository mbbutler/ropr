use crate::{
	binary::{Bitness, Section},
	gadgets::GadgetIterator,
	rules::is_gadget_tail,
};

use disc_v::{rv_decode, Disassembler as RVDisassembler};

const MAX_INSTRUCTION_LENGTH: usize = 15;

pub struct Disassembly<'b> {
	section: &'b Section<'b>,
	bytes: &'b [u8],
	instructions: Vec<rv_decode>,
	file_offset: usize,
}

impl<'b> Disassembly<'b> {
	pub fn new(section: &'b Section) -> Option<Self> {
		let bytes = section.bytes();

		if bytes.is_empty() {
			return None;
		}

		let instructions: Vec<rv_decode> = RVDisassembler::new(
			section.rv_isa(),
			bytes,
			(section.program_base() + section.section_vaddr()) as u64,
		)
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

	pub fn instruction(&self, index: usize) -> Option<&rv_decode> {
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
