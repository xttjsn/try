#[macro_use]
pub mod regs {
	use nix::unistd::Pid;
	use nix::sys::ptrace;

	#[macro_export]
	macro_rules! align {
		($arg:expr, $align:expr) => {
			(($arg) + (($align) - 1)) & !(($align) - 1)
		}
	}

	#[macro_export]
	macro_rules! walign {
		($arg:expr) => {
			align!($arg, 8)
		}
	}

	pub const WORD_SIZE: usize = 8;

	pub type Word = libc::c_ulonglong;
	pub type SWord = libc::c_longlong;

	pub type Reg = Word;
	pub const MAX: Reg = std::u64::MAX;

	pub trait Register {
		fn resolve_string(&self, pid: Pid) -> String;
	}

	impl Register for Reg {
		#[allow(deprecated)]
		fn resolve_string(&self, pid: Pid) -> String {
			let mut bytes: Vec<u8> = Vec::new();

			loop {
				unsafe {
					let word = ptrace::ptrace(ptrace::Request::PTRACE_PEEKDATA,
											  pid,
											  (*self) as *mut core::ffi::c_void,
											  0 as *mut core::ffi::c_void,
					).unwrap();
					let wordbytes = word.to_le_bytes();
					if let Some(idx) = wordbytes.iter().position(|x| *x == 0) {
						bytes.copy_from_slice(&wordbytes[..idx+1]);
						break;
					} else {
						bytes.copy_from_slice(&wordbytes[..]);
					}
				}
			}

			String::from_utf8(bytes).unwrap()
		}
	}

	#[derive(Clone)]
	pub struct UserRegs (pub libc::user_regs_struct);

	pub type RegError = String;

	impl UserRegs {
		pub fn zeroed(curr_regs: &Self) -> Self {
			let mut regs = curr_regs.0.clone();
			regs.rax = 0;
			regs.rdi = 0;
			regs.rsi = 0;
			regs.rdx = 0;
			regs.r10 = 0;
			regs.r8 = 0;
			regs.r9 = 0;
			UserRegs(regs)
		}

		pub fn ip_backup(&mut self) -> Result<(), RegError> {
			self.0.rip -= 2;
			Ok(())
		}

		pub fn set_sysno(&mut self, sysno: nc::sysno::Sysno) -> Result<(), RegError> {
			self.0.rax = sysno as u64;
			Ok(())
		}

		pub fn get_sysno(&self) -> nc::sysno::Sysno {
			self.0.orig_rax as nc::sysno::Sysno
		}

		pub fn get_ret(&self) -> Reg {
			self.0.rax
		}

		pub fn set_ret(&mut self, ret: &Reg) {
			self.0.rax = *ret;
		}

		pub fn get_arguments(&self) -> Vec<Reg> {
			vec![self.0.rdi, self.0.rsi, self.0.rdx,
				 self.0.r10, self.0.r8, self.0.r9]
		}

		pub fn set_argument(&mut self, idx: usize, val: &Reg) -> Result<(), RegError> {
			if idx > 6 {
				Err("More argument than expected".to_owned())
			} else {
				match idx {
					1 => {
						self.0.rdi = val.clone();
					}
					2 => {
						self.0.rsi = val.clone();
					}
					3 => {
						self.0.rdx = val.clone();
					}
					4 => {
						self.0.r10 = val.clone();
					}
					5 => {
						self.0.r8 = val.clone();
					}
					6 => {
						self.0.r9 = val.clone();
					}
					_ => {
						return Err("Invalid index".to_owned());
					}
				};
				Ok(())
			}
		}

		pub fn set_arguments(&mut self, values: &[Reg]) -> Result<(), RegError> {
			if values.len() == 0 {
				Err("No arguments".to_owned())
			}
			else if values.len() > 6 {
				Err("More arguments than expected".to_owned())
			} else {
				for idx in 1..values.len()+1 {
					self.set_argument(idx, &values[idx-1])?;
				}
				Ok(())
			}
		}
	}

	impl Into<libc::user_regs_struct> for UserRegs {
		fn into(self) -> libc::user_regs_struct {
			self.0
		}
	}
}
