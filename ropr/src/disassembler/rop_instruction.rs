pub trait ROPInstruction {
	fn is_ret(&self) -> bool;

	fn is_sys(&self) -> bool;

	fn is_jop(&self, noisy: bool) -> bool;

	fn is_invalid(&self) -> bool;

	fn is_gadget_tail(&self, rop: bool, sys: bool, jop: bool, noisy: bool) -> bool;

	fn is_rop_gadget_head(&self, noisy: bool) -> bool;

	fn is_stack_pivot_head(&self) -> bool;

	fn is_stack_pivot_tail(&self) -> bool;

	fn is_base_pivot_head(&self) -> bool;
}
