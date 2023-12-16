use std::marker::PhantomData;

use crate::disassembler::{ROPFormat, ROPFormatter, ROPInstruction};
use iced_x86::{
	Code, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};

impl ROPFormat<Instruction> for IntelFormatter {
	fn format_instr(&mut self, instr: &Instruction, output: &mut impl iced_x86::FormatterOutput) {
		self.format(instr, output);
	}
}

impl ROPInstruction for Instruction {
	type Formatter = IntelFormatter;

	fn formatter() -> ROPFormatter<Self, Self::Formatter> {
		let mut formatter = IntelFormatter::new();
		let options = iced_x86::Formatter::options_mut(&mut formatter);
		options.set_hex_prefix("0x");
		options.set_hex_suffix("");
		options.set_space_after_operand_separator(true);
		options.set_branch_leading_zeroes(false);
		options.set_uppercase_hex(false);
		options.set_rip_relative_addresses(true);
		ROPFormatter {
			formatter,
			t: PhantomData::<Instruction>,
		}
	}

	fn len(&self) -> usize {
		self.len()
	}

	fn is_ret(&self) -> bool {
		matches!(self.mnemonic(), Mnemonic::Ret)
	}

	fn is_sys(&self) -> bool {
		match self.mnemonic() {
			Mnemonic::Syscall => true,
			Mnemonic::Int => matches!(self.try_immediate(0).unwrap(), 0x80),
			Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => true,
			Mnemonic::Sysret | Mnemonic::Sysretq | Mnemonic::Sysexit | Mnemonic::Sysexitq => true,
			_ => false,
		}
	}

	fn is_jop(&self, noisy: bool) -> bool {
		match self.mnemonic() {
			Mnemonic::Jmp => {
				if noisy {
					!matches!(
						self.op0_kind(),
						OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16
					)
				} else {
					match self.op0_kind() {
						OpKind::Register => true,
						OpKind::Memory => {
							!matches!(self.memory_base(), Register::EIP | Register::RIP)
						}
						_ => false,
					}
				}
			}
			Mnemonic::Call => {
				if noisy {
					!matches!(
						self.op0_kind(),
						OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16
					)
				} else {
					match self.op0_kind() {
						OpKind::Register => true,
						OpKind::Memory => {
							!matches!(self.memory_base(), Register::EIP | Register::RIP)
						}
						_ => false,
					}
				}
			}
			_ => false,
		}
	}

	fn is_invalid(&self) -> bool {
		matches!(self.code(), Code::INVALID)
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
		if !noisy
			&& (self.has_lock_prefix()
				|| self.has_rep_prefix()
				|| self.has_repe_prefix()
				|| self.has_repne_prefix()
				|| self.has_xacquire_prefix()
				|| self.has_xrelease_prefix())
		{
			return false;
		}
		match self.flow_control() {
			FlowControl::Next | FlowControl::Interrupt => true,
			FlowControl::ConditionalBranch => noisy,
			FlowControl::Call => self.mnemonic() != Mnemonic::Call,
			_ => false,
		}
	}

	fn is_stack_pivot_head(&self) -> bool {
		let reg0 = self.op0_register();
		let kind1 = self.op1_kind();
		let reg1 = self.op1_register();
		match self.mnemonic() {
			Mnemonic::Adc
			| Mnemonic::Adcx
			| Mnemonic::Add
			| Mnemonic::Sbb
			| Mnemonic::Sub
			| Mnemonic::Bndmov
			| Mnemonic::Cmova
			| Mnemonic::Cmovae
			| Mnemonic::Cmovb
			| Mnemonic::Cmovbe
			| Mnemonic::Cmove
			| Mnemonic::Cmovg
			| Mnemonic::Cmovge
			| Mnemonic::Cmovl
			| Mnemonic::Cmovle
			| Mnemonic::Cmovne
			| Mnemonic::Cmovno
			| Mnemonic::Cmovnp
			| Mnemonic::Cmovns
			| Mnemonic::Cmovo
			| Mnemonic::Cmovp
			| Mnemonic::Cmovs
			| Mnemonic::Cmpxchg
			| Mnemonic::Cmpxchg16b
			| Mnemonic::Cmpxchg8b
			| Mnemonic::Pop
			| Mnemonic::Popa
			| Mnemonic::Popad => {
				matches!(reg0, Register::RSP | Register::ESP | Register::SP)
					&& matches!(
						kind1,
						OpKind::Immediate8
							| OpKind::Immediate8_2nd | OpKind::Immediate16
							| OpKind::Immediate32 | OpKind::Immediate64
							| OpKind::Immediate8to16 | OpKind::Immediate8to32
							| OpKind::Immediate8to64 | OpKind::Immediate32to64
							| OpKind::Register
					)
			}
			Mnemonic::Mov | Mnemonic::Movbe | Mnemonic::Movd => {
				matches!(reg0, Register::RSP | Register::ESP | Register::SP)
					&& (matches!(kind1, OpKind::Register) || self.memory_base() != Register::None)
			}
			Mnemonic::Xadd | Mnemonic::Xchg => {
				matches!(reg0, Register::RSP | Register::ESP | Register::SP)
					|| matches!(reg1, Register::RSP | Register::ESP | Register::SP)
			}
			Mnemonic::Leave => true,
			_ => false,
		}
	}

	fn is_stack_pivot_tail(&self) -> bool {
		self.is_ret()
	}

	fn is_base_pivot_head(&self) -> bool {
		let reg0 = self.op0_register();
		let kind1 = self.op1_kind();
		let reg1 = self.op1_register();
		match self.mnemonic() {
			Mnemonic::Adc
			| Mnemonic::Adcx
			| Mnemonic::Add
			| Mnemonic::Sbb
			| Mnemonic::Sub
			| Mnemonic::Bndmov
			| Mnemonic::Cmova
			| Mnemonic::Cmovae
			| Mnemonic::Cmovb
			| Mnemonic::Cmovbe
			| Mnemonic::Cmove
			| Mnemonic::Cmovg
			| Mnemonic::Cmovge
			| Mnemonic::Cmovl
			| Mnemonic::Cmovle
			| Mnemonic::Cmovne
			| Mnemonic::Cmovno
			| Mnemonic::Cmovnp
			| Mnemonic::Cmovns
			| Mnemonic::Cmovo
			| Mnemonic::Cmovp
			| Mnemonic::Cmovs
			| Mnemonic::Cmpxchg
			| Mnemonic::Cmpxchg16b
			| Mnemonic::Cmpxchg8b
			| Mnemonic::Pop
			| Mnemonic::Popa
			| Mnemonic::Popad => {
				matches!(reg0, Register::RBP | Register::EBP | Register::BP)
					&& matches!(
						kind1,
						OpKind::Immediate8
							| OpKind::Immediate8_2nd | OpKind::Immediate16
							| OpKind::Immediate32 | OpKind::Immediate64
							| OpKind::Immediate8to16 | OpKind::Immediate8to32
							| OpKind::Immediate8to64 | OpKind::Immediate32to64
							| OpKind::Register
					)
			}
			Mnemonic::Mov | Mnemonic::Movbe | Mnemonic::Movd => {
				matches!(reg0, Register::RBP | Register::EBP | Register::BP)
					&& (matches!(kind1, OpKind::Register) || self.memory_base() != Register::None)
			}
			Mnemonic::Xadd | Mnemonic::Xchg => {
				matches!(reg0, Register::RBP | Register::EBP | Register::BP)
					|| matches!(reg1, Register::RBP | Register::EBP | Register::BP)
			}
			Mnemonic::Enter => true,
			_ => false,
		}
	}

	// fn format(&self, output: &mut impl iced_x86::FormatterOutput) {
	// 	let formatter = FORMATTER.get_or_init(|| {
	// 		let mut formatter = IntelFormatter::new();
	// 		let options = iced_x86::Formatter::options_mut(&mut formatter);
	// 		options.set_hex_prefix("0x");
	// 		options.set_hex_suffix("");
	// 		options.set_space_after_operand_separator(true);
	// 		options.set_branch_leading_zeroes(false);
	// 		options.set_uppercase_hex(false);
	// 		options.set_rip_relative_addresses(true);
	// 		formatter
	// 	});
	// 	formatter.format(&self, output);
	// }
}
