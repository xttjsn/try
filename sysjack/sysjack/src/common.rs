use std::ffi::CString;
use serde_big_array::big_array;
use libc::{sockaddr_un, sa_family_t, c_char};
use serde::{Serialize, Deserialize};

big_array! { BigArray;
			 +108, }

macro_rules! impl_into_cchar_arr {
	($name:ident, $num:expr) => {
		fn $name <T: Into<Vec<u8>>>(s: T) -> [c_char; $num] {
			let mut arr: [c_char; $num] = [0; $num];
			let cstring = CString::new(s).unwrap();
			let i8slice = unsafe {
				&*(cstring.as_bytes_with_nul() as *const [u8] as *const [i8])
			};
			let sz = if i8slice.len() > ($num-1) {($num-1)} else {i8slice.len()};
			arr[..sz].copy_from_slice(&i8slice[..sz]);
			arr
		}
	}
}

impl_into_cchar_arr! {into_cchar_arr_108, 108}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sockaddr_un")]
struct SockaddrUnDef {
	pub sun_family: sa_family_t,
	#[serde(with = "BigArray")]
	pub sun_path: [c_char; 108]
}

#[derive(Serialize, Deserialize)]
pub struct SockaddrUn(
	#[serde(with = "SockaddrUnDef")]
	sockaddr_un
);

impl SockaddrUn {
	pub fn new<T: Into<Vec<u8>>>(sun_family: sa_family_t,
			   sun_path: T) -> Self {
		SockaddrUn ( sockaddr_un {
			sun_family,
			sun_path: into_cchar_arr_108(sun_path),
		})
	}
}
