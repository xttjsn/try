extern crate bincode;
extern crate serde;
#[macro_use]
extern crate serde_big_array;

use std::ffi::{CString};
use libc::{sockaddr_un, sa_family_t};
use nc::{AF_UNIX};
use std::os::raw::c_char;
use std::{fmt};
use serde::{Deserialize, Serialize};

big_array! { BigArray; }

#[repr(C)]
#[derive(Serialize, Deserialize)]
#[serde(remote = "sockaddr_un")]
struct SockaddrUnDef {
	pub sun_family: sa_family_t,
	#[serde(with = "BigArray")]
	pub sun_path: [c_char; 108]
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
struct SockaddrUn(
	#[serde(with = "SockaddrUnDef")]
	sockaddr_un
);

impl fmt::Debug for SockaddrUn {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		// let  = unsafe { &*(&self.0.sun_path[..] as *const [i8] as *const [u8]) };
		let charvec: Vec<u8> = self.0.sun_path[..].iter().cloned().map(|i| i as u8).collect();
		let cstring = unsafe { CString::from_vec_unchecked(charvec) };
		let string = cstring.to_string_lossy();
		write!(fmt, "sun_family: {}\nsun_path: {:?}", &self.0.sun_family, string)
	}
}

fn main() {
	let mut path: [c_char; 108] = [0; 108];
	let sockpath = CString::new("socket").unwrap();
	// unsafe {
	// 	copy_nonoverlapping(sockpath.as_ptr(), &mut addr.sun_path as *mut _, sockpath.as_bytes_with_nul().len());
	// }
	let i8slice = unsafe { &*(sockpath.as_bytes_with_nul() as *const [u8] as *const [i8]) };
	path[..i8slice.len()].copy_from_slice(i8slice);
	let addr = SockaddrUn(sockaddr_un {
		sun_family: AF_UNIX as u16,
		sun_path: path,
	});

	println!("{:?}", addr);

	let bytes = bincode::serialize(&addr).unwrap();
	println!("serialized struct: {:?}", bytes);
}
