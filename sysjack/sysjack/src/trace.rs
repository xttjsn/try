extern crate nc;

use std::collections::BTreeMap;
use std::path::Path;
use std::ffi::CString;
use nix::unistd::Pid;
use nix::unistd::execve;
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::sys::ptrace;
use crate::ctrl::{Script, Activation, Val, SkipControl, Instruction};
use crate::regs::{Word, WORD_SIZE, SWord, Reg, UserRegs, MAX};

pub struct Tracee {
	pid: Pid,
}

impl Tracee {
	pub fn new(pid: Pid) -> Self {
		Tracee {
			pid
		}
	}

	pub fn start(prog_path: &Path) {
		// Normally this function does not return
		ptrace::traceme().unwrap();
		execve(&CString::new(prog_path.to_str().unwrap()).unwrap(), &[], &[]).unwrap();
	}
}

type HookError = String;
type SyncError = String;

pub struct Tracer<'a, A: Activation + Clone> {
	tracee: &'a Tracee,
	hooks: BTreeMap<nc::sysno::Sysno, Script<A>>,
	mregs: BTreeMap<String, UserRegs>,
	mval: BTreeMap<String, Reg>,
	curr_regs: Option<UserRegs>,
}

impl<'a, A: Activation + Clone> Tracer<'a, A> {
	pub fn new(tracee: &'a Tracee) -> Tracer<A> {
		Tracer {
			tracee,
			hooks: BTreeMap::new(),
			mregs: BTreeMap::new(),
			mval: BTreeMap::new(),
			curr_regs: None,
		}
	}

	pub fn hook(&mut self, sysno: nc::sysno::Sysno, script: Script<A>) -> Result<(), HookError> {
		if let Some(_) = self.hooks.get(&sysno) {
			Err(format!("{} is already hooked", sysno))
		} else {
			self.hooks.entry(sysno).or_insert(script);
			Ok(())
		}
	}

	pub fn sync(&mut self) -> Result<(), SyncError> {
		// This method is blocking (normally) until the tracee stops

		// Initial sync with tracee
		// TODO: check waitstatus
		self.init_sync().unwrap();

		loop {
			// Each syscall delivery invokes a script
			let sysno = self.step_syscall()?.get_sysno();
			match self.hooks.remove(&sysno)
			{
				Some(script) => {
					self.run_script(&script).unwrap();
					self.hooks.insert(sysno, script);
				}
				None => {
					self.resume().unwrap();
				}
			}
		}
	}

	fn save_regs(&mut self, regs: &UserRegs, name: &str) {
		self.mregs.entry(name.to_owned()).and_modify(|v| { *v = regs.clone() }).or_insert(regs.clone());
	}

	fn save_reg(&mut self, val: &Reg, name: &str) {
		self.mval.entry(name.to_owned()).and_modify(|v| { *v = val.clone() }).or_insert(val.clone());
	}

	fn set_regs(&self, regs: &UserRegs) -> Result<(), SyncError> {
		ptrace::setregs(self.tracee.pid, regs.clone().into()).unwrap();
		Ok(())
	}

	fn get_regs(&self) -> Result<UserRegs, SyncError> {
		Ok(UserRegs(ptrace::getregs(self.tracee.pid).unwrap()))
	}

	fn resolve_val(&self, val: &Val) -> Result<Reg, SyncError> {
		match val {
			Val::Raw(reg) => Ok(reg.clone()),
			Val::Var(name) => {
				match self.mval.get(&name.to_owned()) {
					None => Err(format!("{} not found", name)),
					Some(val) => Ok(val.clone())
				}
			}
		}
	}

	#[allow(deprecated)]
	fn set_word(&self, addr: *mut Word, data: Word) -> Result<(), SyncError> {
		unsafe {
			ptrace::ptrace(ptrace::Request::PTRACE_POKEDATA,
						   self.tracee.pid,
						   addr as *mut core::ffi::c_void,
						   data as *mut core::ffi::c_void,
			).unwrap();
		}
		Ok(())
	}

	fn init_sync(&self) -> Result<(), SyncError> {
		waitpid(self.tracee.pid, Some(WaitPidFlag::empty())).unwrap();
		ptrace::setoptions(self.tracee.pid, ptrace::Options::PTRACE_O_EXITKILL | ptrace::Options::PTRACE_O_TRACESYSGOOD).unwrap();
		Ok(())
	}

	fn step_syscall(&mut self) -> Result<UserRegs, SyncError> {
		ptrace::syscall(self.tracee.pid, None).unwrap();
		waitpid(self.tracee.pid, Some(WaitPidFlag::empty())).unwrap();
		let regs = UserRegs(ptrace::getregs(self.tracee.pid).unwrap());
		self.curr_regs = Some(regs.clone());
		Ok(regs)
	}

	fn resume(&self) -> Result<(), SyncError> {
		ptrace::detach(self.tracee.pid, None).unwrap();
		Ok(())
	}

	fn run_script(&mut self, script: &Script<A>) -> Result<(), SyncError> {
		// Gather registers and invoke activation
		// TODO: make it platform-independent
		let regs = self.get_regs().unwrap();
		let args = regs.get_arguments();
		if script.starter.activation.signal(&args[..].iter().map(|u| *u).collect::<Vec<Reg>>().as_slice()).unwrap() {
			match &script.starter.skip_ctrl {
				SkipControl::Skip {regs_enter_name} => {
					self.save_regs(&regs, regs_enter_name);
				}
				SkipControl::Keep {regs_enter_name, regs_exit_name, ret_name} => {
					self.save_regs(&regs, regs_enter_name);
					let regs = self.step_syscall()?;
					self.save_regs(&regs, regs_exit_name);
					self.save_reg(&regs.0.rax, ret_name);
				}
			};

			// Execute each instruction
			for instr in script.intrs.iter() {
				match instr {
					Instruction::Call {ctrl, sysno, vals} => {
						let mut base_regs = self.curr_regs.as_ref().unwrap().clone();
						// Reduce instruction pointer to point to syscall again
						base_regs.ip_backup().unwrap();
						base_regs.set_sysno(*sysno).unwrap();
						base_regs.set_arguments(&vals.iter()
												.map(|v| self.resolve_val(v).unwrap())
												.collect::<Vec<Reg>>().as_slice()).unwrap();

						let enter_regs = self.step_syscall()?;
						let exit_regs = self.step_syscall()?;
						self.save_regs(&enter_regs, &ctrl.regs_enter_name);
						self.save_regs(&exit_regs, &ctrl.regs_exit_name);
						self.save_reg(&exit_regs.get_ret(), &ctrl.ret_name);
						self.curr_regs = Some(exit_regs);
					}
					Instruction::Alloc {blob, name} => {
						if blob.len() == 0 {
							return Err("Zero-sized blob".to_owned());
						} else {
							let mut base_regs = self.curr_regs.as_ref().unwrap().clone();
							base_regs.ip_backup().unwrap();
							base_regs.set_sysno(nc::SYS_BRK).unwrap();
							base_regs.set_argument(1, &MAX).unwrap(); // Set the first argument to -1
							self.set_regs(&base_regs).unwrap();

							let _enter_regs = self.step_syscall()?;
							let exit_regs = self.step_syscall()?;
							let current_brk = exit_regs.get_ret();
							if (current_brk as SWord) < 0 {
								return Err("brk() failed".to_owned());
							}
							let target_brk = current_brk + blob.len() as Word * WORD_SIZE as Word;

							base_regs.set_argument(1, &target_brk).unwrap();
							self.set_regs(&base_regs).unwrap();
							let _enter_regs = self.step_syscall()?;
							let exit_regs = self.step_syscall()?;
							let adjusted_brk = exit_regs.get_ret();

							if adjusted_brk != target_brk {
								return Err(format!("brk(). Expecting {}, getting {}", target_brk, adjusted_brk));
							}

							let src = blob.as_slice().as_ptr() as *const Word;
							let dst = current_brk as *mut Word;
							for off in 0..blob.len() {
								let (dstaddr, data) = unsafe {
									(dst.offset(off as isize), *src.offset(off as isize))
								};
								self.set_word(dstaddr, data).unwrap();
							}

							self.save_reg(&current_brk, name);
						}
					}
					Instruction::Ret {val} => {
						let mut base_regs = self.curr_regs.as_ref().unwrap().clone();
						base_regs.set_ret(&self.resolve_val(val).unwrap());
						self.set_regs(&base_regs).unwrap();
						self.resume()?;
					}
				};
			}
			Ok(())
		} else {
			Ok(())
		}
	}
}
