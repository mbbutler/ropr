use crate::binary::Bitness;
use iced_x86::{Decoder, DecoderOptions, Instruction};

pub struct RISCVDisassembler<'b> {
	decoder: Decoder<'b>,
}

impl<'b> RISCVDisassembler<'b> {
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
}
