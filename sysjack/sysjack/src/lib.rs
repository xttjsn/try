extern crate cfg_if;

cfg_if::cfg_if! {
	if #[cfg(target_arch = "x86_64")] {
		#[macro_use]
		mod x86_64;
		pub use self::x86_64::*;
	} else if #[cfg(target_arch = "x86")] {
		#[macro_use]
		mod x86;
		pub use self::x86::*;
	}
}

#[macro_use]
extern crate derive_new;

pub mod ctrl;
pub mod trace;
pub mod util;
pub mod common;
