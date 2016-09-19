//// Bitwise Macros
////
// ROTRIGHT
macro_rules! rot_right {
	($word:expr, $bits:expr) => {
		(($word) >> ($bits)) | (($word) << (32-($bits)))
	}
}
// ROTLEFT
macro_rules! rot_left {
	($word:expr, $bits:expr) => {
		(($word) << ($bits)) | (($word) >> (32-($bits)))
	}
}
// CH
macro_rules! ch {
	($x:expr, $y:expr, $z:expr) => {
		((($x) & ($y)) ^ (!($x) & ($z)))
	}
}
// MAJ
macro_rules! maj {
	($x:expr, $y:expr, $z:expr) => {
		((($x) & ($y)) ^ (($x) & ($z)) ^ (($y) & ($z)))
	}
}
// BSIG0 FUNC1
macro_rules! bsig0 {
	($x:expr) => {
		(rot_right!($x,2) ^ rot_right!($x,13) ^ rot_right!($x,22))
	}
}
// BSIG1 FUNC2
macro_rules! bsig1 {
	($x:expr) => {
		(rot_right!($x,6) ^ rot_right!($x,11) ^ rot_right!($x,25))
	}
}
// SSIG0 FUNC3
macro_rules! ssig0 {
	($x:expr) => {
		rot_right!($x,7) ^ rot_right!($x,18) ^ (($x) >> 3)
	}
}
// SSIG1 FUNC4
macro_rules! ssig1 {
	($x:expr) => {
		rot_right!($x,17) ^ rot_right!($x,19) ^ (($x) >> 10)
	}
}
#[test]
fn test_rot_right_macro() {
	assert_eq!(rot_right!(1,3), 536870912);
}
#[test]
fn test_rot_left_macro() {
	assert_eq!(rot_left!(1,3), 8);
}
#[test]
fn test_ch_macro() {
	assert_eq!(ch!(5,7,8), 13);
}
#[test]
fn test_maj_macro() {
	assert_eq!(maj!(5,7,8), 5);
}
#[test]
fn test_bsig0_macro() {
	assert_eq!(bsig0!(1), 1074267136);
	assert_eq!(bsig0!(3), -1072165888);
}
#[test]
fn test_bsig1_macro() {
	assert_eq!(bsig1!(1), 69206144);
	assert_eq!(bsig1!(3), 207618432);
}
#[test]
fn test_ssig0_macro() {
	assert_eq!(ssig0!(1), 33570816);
	assert_eq!(ssig0!(3), 100712448);
}
#[test]
fn test_ssig1_macro() {
	assert_eq!(ssig1!(1), 40960);
	assert_eq!(ssig1!(3), 122880);
}

//// Preprocessing functions
////
//   Solves for k in (l+1+k)/512 = 448
fn k_of_l(l: u64) -> u64 {
	let remainder_after_last_512: u64 = (l + 1) % 512;

	let k: u64 = match remainder_after_last_512 {
		ref rem_k if *rem_k <= 448 => {
			448 - *rem_k
		},
		ref rem_k if *rem_k > 448 => {
			(512 - *rem_k) + 448
		}
		_ => panic!("Some how your input is not less than or equal to 448, nor is it greater than 448. So don't quote me or anything but my best guess is you input has gone quantim."),
	};

	k
}

#[test]
fn test_ko_of_l() {
	assert_eq!(k_of_l(837), 122);
	assert_eq!(k_of_l(40), 407);
	assert_eq!(k_of_l(449), 510);
	assert_eq!(k_of_l(961), 510);
}

// Preprocess Message for SHA256
// NIST SPEC: http://tools.ietf.org/html/rfc6234#page-8
fn preprocess_message(message: &mut Vec<u8>, l: u64, k: u64) {
	// Add a 1 we have 7 0 bits that need to be allocated to K or K and L depending upon context
	let mut appenditure: Vec<u8> = vec![0b10000000];
	// Append k 0s
	let rem_k = k - 7;
	if rem_k > 0 {
		let mut rem_vec: Vec<u8> = vec![0b00000000; (rem_k/8) as usize];
		appenditure.append(&mut rem_vec)
	}
	// Obtain binary representation of L
	let l_as_bytes: [u8; 8] = unsafe {std::mem::transmute(l)};
	let mut l_v: Vec<u8> = From::from(&l_as_bytes[..]);
	l_v.reverse();
	// Apend L to appenditure
	appenditure.append(&mut l_v);
	// Apend appenditure to message
	message.append(&mut appenditure);
}

#[test]
fn test_preprocess_message() {
	let mut message: Vec<u8> = vec![0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101];
	let byte_length = message.len();
	let bit_length = (byte_length * 8) as u64;
	preprocess_message(&mut message, bit_length, k_of_l(bit_length));

	let target: Vec<u8> = vec![97, 98, 99, 100, 101, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40];
	assert_eq!(message.len(), 64);
	assert_eq!(message, target);
}

const K_SEQUENCE: [u32; 64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

pub fn sha256_of_message_as_u8_vec( message: &mut Vec<u8> ) -> Box<Vec<u8>> {
	let mut message_schedule: [u32; 64] = [0;64];

	// Get Size of message in bits and bytes
	let byte_length = message.len();
	let bit_length = (byte_length * 8) as u64;
	preprocess_message(message, bit_length, k_of_l(bit_length));
	
	// Break message into 512 blocks or a vector of vectors containing 64 u8 elements
	let part_size = 64;
	let number_of_parts = message.len() / part_size;
	let mut message_blocks: Vec<Vec<u8>> = Vec::with_capacity(number_of_parts);
	for _ in 0..number_of_parts {
		let at: usize = message.len() - part_size;
		let mut new_part = message.split_off(at);
		new_part.reverse();
		message_blocks.push(new_part);
	}
	message_blocks.reverse();
	let num_of_blocks = message_blocks.len();

	let mut blocks_as_16_u32s: Vec<Vec<u32>> = Vec::with_capacity(message_blocks.len());

	let mut hash_value: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
	let mut all_hashes: Vec<Vec<u32>> = Vec::with_capacity( num_of_blocks + 1 );
	let mut new_hash_value: Vec<u32> = Vec::with_capacity(8);
	new_hash_value.extend(hash_value.iter());
	all_hashes.push(new_hash_value);

	// // For each 512 bit block
	for i in 0..num_of_blocks  {
		let message_block = &mut message_blocks[i];
		// Convert u8 elements into u32 elements
		let mut m: [u32;16] = [0;16];
		for i in 0..16 {
			let at: usize = message_block.len() - 4;
			let mut new_part_as_bytes = message_block.split_off(at);
			new_part_as_bytes.reverse();
			let new_part: u32 = ((new_part_as_bytes[0] as u32) << 24) + ((new_part_as_bytes[1] as u32) << 16) + ((new_part_as_bytes[2] as u32) << 8) + (new_part_as_bytes[3] as u32);
			m[i] = new_part;
		}
		let mut m_printer: Vec<u32> = Vec::with_capacity(16);
		m_printer.extend(&m);
		blocks_as_16_u32s.push(m_printer);

		//// Begin checksum processing
		// Prepare message scheduler
		// requires message block
		for t in 0..16 {
			message_schedule[t] = m[t];
		}
		for t in 16..64 {
			let part_1 = ssig1!(message_schedule[t-2]);
			let part_2 = message_schedule[t-7];
			let part_3 = ssig0!(message_schedule[t-15]);
			let part_4 = message_schedule[t-16];
			message_schedule[t] = part_1.wrapping_add(part_2).wrapping_add(part_3).wrapping_add(part_4);
		}

		let mut message_schedule_as_vec: Vec<u32> = Vec::with_capacity(64);
		message_schedule_as_vec.extend(message_schedule.iter());
		// message_schedule_printer.push(message_schedule_as_vec);

		// Prepare working variables with previous hash values
		// requires previous hash
		let mut a = hash_value[0];
		let mut b = hash_value[1];
		let mut c = hash_value[2];
		let mut d = hash_value[3];
		let mut e = hash_value[4];
		let mut f = hash_value[5];
		let mut g = hash_value[6];
		let mut h = hash_value[7];

		// Compute itermediats with message_schedule
		// Requires message_schedule and previous a-h
		// Can solve for current a-h
		for t in 0..64 {
			let t1 = h.wrapping_add(bsig1!(e)).wrapping_add(ch!(e,f,g)).wrapping_add(K_SEQUENCE[t]).wrapping_add(message_schedule[t]);
			let t2 = bsig0!(a).wrapping_add(maj!(a,b,c));
			h = g;
			g = f;
			f = e;
			e = d.wrapping_add(t1);
			d = c;
			c = b;
			b = a;
			a = t1.wrapping_add(t2);
		}

		// Add result back to hash
		// Dependancies: a-h
		// Can solve for previous hash
		hash_value[0] = hash_value[0].wrapping_add(a);
		hash_value[1] = hash_value[1].wrapping_add(b);
		hash_value[2] = hash_value[2].wrapping_add(c);
		hash_value[3] = hash_value[3].wrapping_add(d);
		hash_value[4] = hash_value[4].wrapping_add(e);
		hash_value[5] = hash_value[5].wrapping_add(f);
		hash_value[6] = hash_value[6].wrapping_add(g);
		hash_value[7] = hash_value[7].wrapping_add(h);

		let mut new_hash_value: Vec<u32> = Vec::with_capacity(8);
		new_hash_value.extend(hash_value.iter());
		all_hashes.push(new_hash_value);

		let mut end_hash_printer: Vec<u32> = Vec::with_capacity(8);
		end_hash_printer.extend(hash_value.iter());
	};

	let mut resulting_hash_bytes: Box<Vec<u8>> = Box::new(Vec::with_capacity(32));
	for hash_value in hash_value.iter() {
		let bytes_of_hash: [u8; 4] = unsafe {std::mem::transmute(*hash_value)};
		for i in 0..4 {
			let index = 3 - i;
			(*resulting_hash_bytes).push(bytes_of_hash[index]);
		}
	}

	resulting_hash_bytes
}

#[test]
fn test_sha256_of_message_as_u8_vec() {
	// From "Mu Shall Rise! And with it so shall too, sweet liberty echo through the chamber halls, both high and low, and big and small."
	let mut message: Vec<u8> = vec![77, 117, 32, 83, 104, 97, 108, 108, 32, 82, 105, 115, 101, 33, 32, 65, 110, 100, 32, 119, 105, 116, 104, 32, 105, 116, 32, 115, 111, 32, 115, 104, 97, 108, 108, 32, 116, 111, 111, 44, 32, 115, 119, 101, 101, 116, 32, 108, 105, 98, 101, 114, 116, 121, 32, 101, 99, 104, 111, 32, 116, 104, 114, 111, 117, 103, 104, 32, 116, 104, 101, 32, 99, 104, 97, 109, 98, 101, 114, 32, 104, 97, 108, 108, 115, 44, 32, 98, 111, 116, 104, 32, 104, 105, 103, 104, 32, 97, 110, 100, 32, 108, 111, 119, 44, 32, 97, 110, 100, 32, 98, 105, 103, 32, 97, 110, 100, 32, 115, 109, 97, 108, 108, 46];
	let result: Vec<u8> = *sha256_of_message_as_u8_vec(&mut message);
	let expected: Vec<u8> = vec![61, 186, 202, 92, 52, 61, 155, 63, 150, 130, 106, 106, 206, 202, 234, 155, 196, 116, 142, 225, 90, 173, 181, 137, 94, 173, 27, 211, 63, 132, 41, 112];
	assert_eq!(result, expected);
}