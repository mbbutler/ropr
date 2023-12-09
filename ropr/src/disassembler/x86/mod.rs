use crate::binary::{Bitness, Section};
use iced_x86::{Decoder, DecoderOptions, Instruction};

use super::Disassembly;

pub mod x86_instruction;

pub struct X86Disassembler<'b> {
	decoder: Decoder<'b>,
}

impl<'b> X86Disassembler<'b> {
	pub fn new(bitness: Bitness, bytes: &'b [u8]) -> Self {
		let decoder = {
			let bitness = match bitness {
				Bitness::Bits32 => 32,
				Bitness::Bits64 => 64,
			};
			let options = DecoderOptions::AMD;
			Decoder::new(bitness, bytes, options)
		};
		Self { decoder }
	}

	pub fn decode_at_offset(&mut self, ip: u64, offset: usize, out: &mut Instruction) {
		self.decoder.set_ip(ip);
		self.decoder.try_set_position(offset).unwrap();
		self.decoder.decode_out(out);
	}

	pub fn disassemble(section: &'b Section) -> Option<Disassembly<'b, Instruction>> {
		let bytes = section.bytes();

		if bytes.is_empty() {
			return None;
		}

		let mut instructions = vec![Instruction::default(); bytes.len()];
		let mut disassembler = Self::new(section.bitness(), bytes);

		// Fully disassemble program - cache for later use when finding gadgets
		instructions
			.iter_mut()
			.enumerate()
			.for_each(|(n, instruction)| {
				disassembler.decode_at_offset(
					(section.program_base() + section.section_vaddr() + n) as u64,
					n,
					instruction,
				)
			});

		Some(Disassembly {
			section,
			bytes,
			instructions,
			file_offset: section.program_base() + section.section_vaddr(),
		})
	}
}
