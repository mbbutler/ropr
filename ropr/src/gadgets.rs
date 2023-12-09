use crate::disassembler::ROPInstruction;
use iced_x86::{Formatter, FormatterOutput, FormatterTextKind};
use std::hash::Hash;

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct Gadget<T: ROPInstruction> {
	instructions: Vec<T>,
	unique_id: usize,
}

impl<T: ROPInstruction> Gadget<T> {
	pub fn instructions(&self) -> &[T] {
		&self.instructions
	}

	pub fn is_stack_pivot(&self) -> bool {
		match self.instructions.as_slice() {
			[] => false,
			[t] => t.is_stack_pivot_tail(),
			[h @ .., _] => h.iter().any(ROPInstruction::is_stack_pivot_head),
		}
	}

	pub fn is_base_pivot(&self) -> bool {
		match self.instructions.as_slice() {
			[] | [_] => false,
			[h @ .., _] => h.iter().any(ROPInstruction::is_base_pivot_head),
		}
	}

	pub fn format_instruction(&self, output: &mut impl FormatterOutput) {
		let mut formatter = T::formatter();
		// Write instructions
		let mut instructions = self.instructions.iter().peekable();
		while let Some(i) = instructions.next() {
			formatter.format(i, output);
			output.write(";", FormatterTextKind::Text);
			if instructions.peek().is_some() {
				output.write(" ", FormatterTextKind::Text);
			}
		}
	}
}

pub struct GadgetIterator<'d, T: ROPInstruction> {
	section_start: usize,
	tail_instruction: T,
	predecessors: &'d [T],
	max_instructions: usize,
	noisy: bool,
	uniq: bool,
	start_index: usize,
	finished: bool,
}

impl<'d, T: ROPInstruction> GadgetIterator<'d, T> {
	pub fn new(
		section_start: usize,
		tail_instruction: T,
		predecessors: &'d [T],
		max_instructions: usize,
		noisy: bool,
		uniq: bool,
		start_index: usize,
	) -> Self {
		Self {
			section_start,
			tail_instruction,
			predecessors,
			max_instructions,
			noisy,
			uniq,
			start_index,
			finished: false,
		}
	}
}

impl<T: ROPInstruction> Iterator for GadgetIterator<'_, T> {
	type Item = (Gadget<T>, usize);

	fn next(&mut self) -> Option<Self::Item> {
		let mut instructions = Vec::new();

		'outer: while !self.predecessors.is_empty() {
			instructions.clear();
			let len = self.predecessors.len();
			let mut index = 0;
			while index < len && instructions.len() < self.max_instructions - 1 {
				let instruction = self.predecessors[index];
				if !instruction.is_rop_gadget_head(self.noisy) {
					// Found a bad
					self.predecessors = &self.predecessors[1..];
					self.start_index += 1;
					continue 'outer;
				}
				instructions.push(instruction);
				index += instruction.len();
			}

			let current_start_index = self.start_index;

			self.predecessors = &self.predecessors[1..];
			self.start_index += 1;

			if index == len {
				instructions.push(self.tail_instruction);
				// instructions.shrink_to_fit();
				let unique_id = if self.uniq {
					0
				} else {
					self.section_start + current_start_index
				};
				return Some((
					Gadget {
						instructions,
						unique_id,
					},
					self.section_start + current_start_index,
				));
			}
		}

		if !self.finished {
			self.finished = true;
			instructions.clear();
			instructions.push(self.tail_instruction);
			let unique_id = if self.uniq {
				0
			} else {
				self.section_start + self.start_index
			};
			return Some((
				Gadget {
					instructions,
					unique_id,
				},
				self.section_start + self.start_index,
			));
		}

		None
	}
}
