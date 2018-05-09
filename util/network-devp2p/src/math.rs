// Copyright 2018 Coinbase, Inc.
// Copyright 2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

static FASTLOG_B: [u64; 6] = [0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000, 0xFFFFFFFF00000000];
static FASTLOG_S: [usize; 6] = [1, 2, 4, 8, 16, 32];

/// Trait defines base 2 log operation on unsigned integer types, rounded down to the nearest
/// integer.
pub trait FastLog {
	fn log2(v: Self) -> usize;
}

macro_rules! fast_log2_impl {
	($t:ty, $log_log_limit:expr) => (
		// Efficiently implemented using bit manipulations to binary search for the index of most
		// significant bit set.
		//
		// See: http://graphics.stanford.edu/~seander/bithacks.html#IntegerLog
		impl FastLog for $t {
			#[inline]
			fn log2(v: $t) -> usize {
				if v == 0 {
					panic!("FastLog::log2 cannot be called with 0");
				}

				let mut v = v as u64;
				let mut r = 0;
				for i in (0..$log_log_limit).rev() {
					if v & FASTLOG_B[i] != 0 {
						v >>= FASTLOG_S[i];
						r |= FASTLOG_S[i];
					}
				}
				r
			}
		}
	)
}

fast_log2_impl!(u8,  3);
fast_log2_impl!(u16, 4);
fast_log2_impl!(u32, 5);
fast_log2_impl!(u64, 6);

#[cfg(test)]
mod tests {
	use super::*;
	use rand::random;

	#[test]
	fn fastlog_is_correct() {
		for _i in 0..51 {
			let v: u64 = random();
			if v == 0 {
				continue;
			}
			assert_eq!(FastLog::log2(v), (v as f64).log2() as usize);

			let v = v as u32;
			if v == 0 {
				continue;
			}
			assert_eq!(FastLog::log2(v), (v as f64).log2() as usize);

			let v = v as u16;
			if v == 0 {
				continue;
			}
			assert_eq!(FastLog::log2(v), (v as f64).log2() as usize);

			let v = v as u8;
			if v == 0 {
				continue;
			}
			assert_eq!(FastLog::log2(v), (v as f64).log2() as usize);
		}
	}

	#[test]
	#[should_panic]
	fn fastlog_zero_panics() {
		FastLog::log2(0u64);
	}
}
