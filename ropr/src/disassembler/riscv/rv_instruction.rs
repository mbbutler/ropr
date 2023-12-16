use std::{
	fmt::Display,
	hash::{Hash, Hasher},
	marker::PhantomData,
};

use disc_v::{
	format::format_component, opcode_data::opcode_data, rv_codec, rv_decode, rv_ireg, rv_op,
	rv_options,
};
use iced_x86::{FlowControl, FormatterTextKind};

use crate::disassembler::{ROPFormat, ROPFormatter, ROPInstruction};

pub struct RVFormatter {
	options: rv_options,
}

impl RVFormatter {
	fn new() -> Self {
		Self {
			options: rv_options {
				reg_nicknames: true,
				resolve_offsets: false,
			},
		}
	}
}

impl ROPFormat<RVInstruction> for RVFormatter {
	fn format_instr(&mut self, instr: &RVInstruction, output: &mut impl iced_x86::FormatterOutput) {
		output.write(&instr.format(&self.options), FormatterTextKind::Text);
	}
}

#[derive(Clone)]
pub struct RVInstruction {
	pub instr: rv_decode,
}

impl Default for RVInstruction {
	fn default() -> Self {
		Self {
			instr: rv_decode {
				pc: 0,
				inst: 0,
				len: 0,
				imm: 0,
				op: rv_op::illegal,
				codec: rv_codec::illegal,
				rd: 0,
				rs1: 0,
				rs2: 0,
				rs3: 0,
				rm: 0,
				pred: 0,
				succ: 0,
				aq: false,
				rl: false,
			},
		}
	}
}

impl RVInstruction {
	pub fn new(instr: rv_decode) -> Self {
		Self { instr }
	}

	fn format(&self, options: &rv_options) -> String {
		let mut buf = String::new();
		for ch in opcode_data[self.instr.op as usize].format.chars() {
			match ch {
				'\t' => {
					buf.push(' ');
				}
				_ => {
					format_component(&mut buf, ch, &self.instr, options);
				}
			}
		}
		buf
	}

	fn modifies_reg(&self, target_reg: u8) -> bool {
		match self.instr.rd {
			reg if reg == target_reg => match self.instr.op {
				rv_op::mv
				| rv_op::c_mv
				| rv_op::add
				| rv_op::addw
				| rv_op::addd
				| rv_op::addi
				| rv_op::addiw
				| rv_op::addid
				| rv_op::c_add
				| rv_op::c_addi
				| rv_op::c_addiw
				| rv_op::c_addi4spn
				| rv_op::c_addi16sp
				| rv_op::c_addw
				| rv_op::sub
				| rv_op::subw
				| rv_op::subd
				| rv_op::c_sub
				| rv_op::c_subw
				| rv_op::lb
				| rv_op::lbu
				| rv_op::lh
				| rv_op::lhu
				| rv_op::lw
				| rv_op::lwu
				| rv_op::ld
				| rv_op::ldu
				| rv_op::lq
				| rv_op::lr_w
				| rv_op::lr_d
				| rv_op::lr_q
				| rv_op::li
				| rv_op::lui
				| rv_op::c_lw
				| rv_op::c_ld
				| rv_op::c_lq
				| rv_op::c_li
				| rv_op::c_lui
				| rv_op::c_lwsp
				| rv_op::c_ldsp
				| rv_op::c_lqsp
				| rv_op::amoadd_w
				| rv_op::amoadd_d
				| rv_op::amoadd_q
				| rv_op::amoswap_w
				| rv_op::amoswap_d
				| rv_op::amoswap_q => true,
				_ => false,
			},
			_ => false,
		}
	}

	fn flow_control(&self) -> FlowControl {
		match self.instr.op {
			rv_op::ret => FlowControl::Return,
			rv_op::jalr | rv_op::c_jr | rv_op::c_jalr | rv_op::jr => FlowControl::IndirectBranch,
			rv_op::jal | rv_op::c_jal | rv_op::c_j | rv_op::j => FlowControl::UnconditionalBranch,
			rv_op::ecall => FlowControl::Call,
			rv_op::beq
			| rv_op::bne
			| rv_op::blt
			| rv_op::bge
			| rv_op::bltu
			| rv_op::bgeu
			| rv_op::c_beqz
			| rv_op::c_bnez => FlowControl::ConditionalBranch,
			_ => FlowControl::Next,
		}
	}
}

impl Eq for RVInstruction {}

impl PartialEq for RVInstruction {
	fn eq(&self, other: &Self) -> bool {
		self.instr.inst == other.instr.inst
	}
}

impl Hash for RVInstruction {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.instr.inst.hash(state);
	}
}

impl Display for RVInstruction {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let options = rv_options {
			reg_nicknames: true,
			resolve_offsets: false,
		};
		write!(f, "{}", &self.format(&options))
	}
}

impl ROPInstruction for RVInstruction {
	type Formatter = RVFormatter;

	fn formatter() -> ROPFormatter<Self, Self::Formatter> {
		let formatter = RVFormatter::new();
		ROPFormatter {
			formatter,
			t: PhantomData::<RVInstruction>,
		}
	}

	fn len(&self) -> usize {
		self.instr.len
	}

	fn is_ret(&self) -> bool {
		matches!(self.instr.op, rv_op::ret)
	}

	fn is_sys(&self) -> bool {
		self.instr.op == rv_op::ecall
	}

	fn is_jop(&self, noisy: bool) -> bool {
		match self.flow_control() {
			FlowControl::IndirectBranch => true,
			FlowControl::UnconditionalBranch => noisy,
			_ => false,
		}
	}

	fn is_invalid(&self) -> bool {
		self.instr.op == rv_op::illegal
	}

	fn is_gadget_tail(&self, rop: bool, sys: bool, jop: bool, noisy: bool) -> bool {
		if self.is_invalid() {
			return false;
		}
		if self.flow_control() == FlowControl::Next {
			return false;
		}
		if rop && self.is_ret() {
			return true;
		}
		if sys && self.is_sys() {
			return true;
		}
		if jop && self.is_jop(noisy) {
			return true;
		}
		false
	}

	fn is_rop_gadget_head(&self, noisy: bool) -> bool {
		if self.is_invalid() {
			return false;
		}
		match self.flow_control() {
			FlowControl::Next | FlowControl::Interrupt | FlowControl::Call => true,
			FlowControl::ConditionalBranch => noisy,
			_ => false,
		}
	}

	fn is_stack_pivot_head(&self) -> bool {
		self.modifies_reg(rv_ireg::sp as u8)
	}

	fn is_stack_pivot_tail(&self) -> bool {
		self.is_ret()
	}

	fn is_base_pivot_head(&self) -> bool {
		self.modifies_reg(rv_ireg::s0 as u8)
	}

	// fn format(&self, output: &mut impl iced_x86::FormatterOutput) {
	// 	output.write(&format_inst(40, &self.instr), FormatterTextKind::Text);
	// }
}
