use iced_x86::FormatterOutput;

use crate::{binary::Section, gadgets::GadgetIterator};

pub mod riscv;
pub mod x86;

const MAX_INSTRUCTION_LENGTH: usize = 15;

pub struct Disassembly<'b, T: ROPInstruction> {
	section: &'b Section<'b>,
	bytes: &'b [u8],
	instructions: Vec<T>,
	file_offset: usize,
}

impl<'b, T: ROPInstruction> Disassembly<'b, T> {
	pub fn bytes(&self) -> &[u8] {
		self.bytes
	}

	pub fn file_offset(&self) -> usize {
		self.file_offset
	}

	pub fn instruction(&self, index: usize) -> Option<&T> {
		self.instructions.get(index)
	}

	pub fn is_tail_at(&self, index: usize, rop: bool, sys: bool, jop: bool, noisy: bool) -> bool {
		self.instructions[index].is_gadget_tail(rop, sys, jop, noisy)
	}

	pub fn gadgets_from_tail(
		&self,
		tail_index: usize,
		max_instructions: usize,
		noisy: bool,
		uniq: bool,
	) -> GadgetIterator<T> {
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

pub trait ROPFormatter<T: ROPInstruction> {
	fn format(instr: &T, output: &mut impl FormatterOutput);
}

pub trait ROPInstruction {
	type Format;

	fn len(&self) -> usize;

	fn is_ret(&self) -> bool;

	fn is_sys(&self) -> bool;

	fn is_jop(&self, noisy: bool) -> bool;

	fn is_invalid(&self) -> bool;

	fn is_gadget_tail(&self, rop: bool, sys: bool, jop: bool, noisy: bool) -> bool;

	fn is_rop_gadget_head(&self, noisy: bool) -> bool;

	fn is_stack_pivot_head(&self) -> bool;

	fn is_stack_pivot_tail(&self) -> bool;

	fn is_base_pivot_head(&self) -> bool;

	fn formatter() -> dyn ROPFormatter<Self::Format>;
}
