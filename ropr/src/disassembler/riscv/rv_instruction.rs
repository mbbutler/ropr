use disc_v::{rv_decode, rv_ireg, rv_op};
use iced_x86::{FlowControl, FormatterOutput};

use crate::disassembler::{ROPFormatter, ROPInstruction};

pub struct RVInstruction {
	instr: rv_decode,
}

impl RVInstruction {
	pub fn new(instr: rv_decode) -> Self {
		Self { instr }
	}

	fn modifies_reg(&self, target_reg: u8) -> bool {
		match self.instr.rd {
			target_reg => match self.instr.op {
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

pub struct RVFormatter {}

impl ROPFormatter<T> for RVFormatter {
	fn format(&self, instr: &RVInstruction, output: &mut impl FormatterOutput) {}
}

impl ROPInstruction for RVInstruction {
	type Format = RVInstruction;

	fn formatter() -> dyn ROPFormatter<Self::Format> {
		RVFormatter {}
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
}
