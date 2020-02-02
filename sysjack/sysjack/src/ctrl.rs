extern crate nc;

use crate::regs::{Reg, Word};

#[derive(Clone)]
pub enum SkipControl {
	// Skip the syscall
	Skip { regs_enter_name: String },
	// Perform the syscall
	Keep { regs_enter_name: String, regs_exit_name: String, ret_name: String }
}

#[derive(Clone)]
pub enum FailControl {
	// Return the value of the first failed syscall
	Default,
	// Fallback to the original syscall
	// (has no effect when the original syscall fails)
	Fallback,
}

#[derive(Clone)]
pub enum Val {
	// Raw value
	Raw(Reg),
	// Named variable
	Var(String),
}

#[derive(Debug)]
pub enum ActivationError {
	ArgumentNotEnough,
}

#[derive(Clone, new)]
pub struct CallControl {
	pub regs_enter_name: String,
	pub regs_exit_name: String,
	pub ret_name: String
}

pub trait Activation {
	fn signal(&self, args: &[Reg]) -> Result<bool, ActivationError>;
}

impl Activation for &dyn Fn(Reg) -> bool {
	fn signal(&self, args: &[Reg]) -> Result<bool, ActivationError> {
		if args.len() < 1 {
			Err(ActivationError::ArgumentNotEnough)
		} else {
			Ok((*self)(args[0].clone()))
		}
	}
}

impl Activation for &dyn Fn(Reg, Reg) -> bool {
	fn signal(&self, args: &[Reg]) -> Result<bool, ActivationError> {
		if args.len() < 2 {
			Err(ActivationError::ArgumentNotEnough)
		} else {
			Ok((*self)(args[0].clone(),
					  args[1].clone()))
		}
	}
}

impl Activation for &dyn Fn(Reg, Reg, Reg) -> bool {
	fn signal(&self, args: &[Reg]) -> Result<bool, ActivationError> {
		if args.len() < 3 {
			Err(ActivationError::ArgumentNotEnough)
		} else {
			Ok((*self)(args[0].clone(),
					  args[1].clone(),
					  args[2].clone()))
		}
	}
}

impl Activation for &dyn Fn(Reg, Reg, Reg, Reg) -> bool {
	fn signal(&self, args: &[Reg]) -> Result<bool, ActivationError> {
		if args.len() < 4 {
			Err(ActivationError::ArgumentNotEnough)
		} else {
			Ok((*self)(args[0].clone(),
					  args[1].clone(),
					  args[2].clone(),
					  args[3].clone()))
		}
	}
}

#[derive(Clone)]
pub struct ScriptStarter<A: Activation>
{
 	pub activation: A,
 	pub skip_ctrl: SkipControl,
}

impl<A: Activation> ScriptStarter<A> {
	pub fn new(activation: A, skip_ctrl: SkipControl) -> Self {
		ScriptStarter {
			activation,
			skip_ctrl
		}
	}
}

#[derive(Clone)]
pub enum Instruction {
	Call{ ctrl: CallControl, sysno: nc::sysno::Sysno, vals: Vec<Val> },
	Alloc{ blob: Vec<Word>, name: String },
	Ret{ val: Val },
}

#[derive(Clone)]
pub struct Script<A: Activation> {
	pub starter: ScriptStarter<A>,
	pub fail_ctrl: FailControl,
	pub intrs: Vec<Instruction>,
}

impl<A: Activation> Script<A> {
	pub fn builder() -> ScriptBuilder<A> {
		ScriptBuilder {
			starter: None,
			fail_ctrl: None,
			intrs: Vec::new()
		}
	}
}

pub struct ScriptBuilder<A: Activation> {
	starter: Option<ScriptStarter<A>>,
	fail_ctrl: Option<FailControl>,
	intrs: Vec<Instruction>
}

type ScriptBuilderError = String;

#[allow(dead_code)]
impl<A: Activation> ScriptBuilder<A> {
	pub fn new(&mut self,
			   starter: ScriptStarter<A>,
			   fail_ctrl: FailControl) -> &mut Self {
		self.starter = Some(starter);
		self.fail_ctrl = Some(fail_ctrl);
		self
	}

	pub fn call(&mut self,
				ctrl: CallControl,
				sysno: nc::sysno::Sysno,
				vals: Vec<Val>) -> &mut Self {
		self.intrs.push(Instruction::Call {
			ctrl,
			sysno,
			vals
		});
		self
	}

	pub fn alloc(&mut self,
				 blob: Vec<Word>,
				 name: String) -> &mut Self {
		self.intrs.push(Instruction::Alloc {
			blob,
			name
		});
		self
	}

	pub fn ret(&mut self,
			   val: Val) -> &mut Self {
		self.intrs.push(Instruction::Ret {
			val
		});
		self
	}

	pub fn build(self) -> Result<Script<A>, ScriptBuilderError> {
		if let None = self.starter {
			Err("No script starter".to_owned())
		} else {
			if self.intrs.len() < 1 {
				Err("no instruction".to_owned())
			} else {
				if let Some(Instruction::Ret {..}) = self.intrs.last() {
					Ok(Script {
						starter: self.starter.unwrap(),
						fail_ctrl: self.fail_ctrl.unwrap(),
						intrs: self.intrs
					})
				} else {
					Err("the last instruction is not Ret".to_owned())
				}
			}
		}
	}
}
