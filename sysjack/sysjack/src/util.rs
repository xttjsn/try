use crate::regs::{Word};
use byte_slice_cast::*;

use serde::Serialize;

pub fn struct2words<T: Serialize>(obj: T) -> Vec<Word> {
	let mut bytes = bincode::serialize(&obj).unwrap();
	let target_len = walign!(bytes.len());

	// Push zero pads
	for _ in bytes.len()..target_len {
		bytes.push(0);
	}

	bytes.as_slice_of::<Word>().unwrap().into()
}
