#[derive(PartialEq)]
pub enum LoadSource {
	Register(&'static str),
	Stack(usize),
	Heap(usize),
	Immediate(usize),
}

#[derive(PartialEq)]
pub enum StoreTarget {
	Register(&'static str),
	Stack(usize),
	Heap(usize),
}

#[derive(PartialEq)]
pub enum JumpTarget {
	Register(&'static str),
	Imm(usize),
}

#[derive(PartialEq)]
pub enum ROPOp {
	Load(LoadSource),
	Store(StoreTarget),
	Jump(JumpTarget),
	Ret,
	Syscall,
	Other,
}

#[derive(PartialEq)]
pub enum ROPOpSize {
	Byte,
	Word,
	Double,
	Quad,
}

pub struct ROPInstruction {
	pub addr: usize,
	pub reg: &'static str,
	pub op: ROPOp,
	// pub opsize: ROPOpSize,
	// pub instr: String,
}

impl ROPInstruction {
	fn load_reg(&self, reg: &str) -> bool {
		self.reg == reg && matches!(self.op, ROPOp::Load(..))
	}

	fn store_reg(&self, reg: &str) -> bool {
		self.reg == reg && matches!(self.op, ROPOp::Store(..))
	}

	fn is_ret(&self) -> bool {
		self.op == ROPOp::Ret
	}

	fn is_syscall(&self) -> bool {
		self.op == ROPOp::Syscall
	}

	fn jump(&self) -> Option<JumpTarget> {
		match self.op {
			ROPOp::Jump(target) => Some(target),
			_ => None,
		}
	}

	fn load(&self) -> Option<LoadSource> {
		match self.op {
			ROPOp::Load(source) => Some(source),
			_ => None,
		}
	}

	fn store(&self) -> Option<StoreTarget> {
		match self.op {
			ROPOp::Store(target) => Some(target),
			_ => None,
		}
	}
}
