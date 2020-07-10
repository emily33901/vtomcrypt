module aes

[typedef]
struct C.symmetric_key {}

fn C.aes_setup() int
fn C.aes_ecb_decrypt() int
fn C.aes_ecb_encrypt() int

pub fn ecb_decrypt_into(key, @in []byte, mut out []byte) {
	skey := C.symmetric_key{}
	
	// schedule key
	mut res := C.aes_setup(key.data, key.len, 0, &skey)

	if res != 0 {
		panic('Unable to schedule key $res')
	}

	res = C.aes_ecb_decrypt(@in.data, out.data, &skey)

	if res != 0 {
		panic('Unable to decrypt block $res')
	}
}

pub fn ecb_encrypt_into(key, @in []byte, mut out []byte) {
	skey := C.symmetric_key{}
	
	// schedule key
	mut res := C.aes_setup(key.data, key.len, 0, &skey)

	if res != 0 {
		panic('Unable to schedule key $res')
	}

	res = C.aes_ecb_encrypt(@in.data, out.data, &skey)

	if res != 0 {
		panic('Unable to encrypt block $res')
	}
}

// taken from the tomcrypt openssl-enc example
fn pkcs7_pad(mut buf []byte, block_length int, is_padding bool) {
	nb := buf.len

	if is_padding {
		/* We are PADDING this block (and therefore adding bytes) */
		/* The pad value in PKCS#7 is the number of bytes remaining in
			the block, so for a 16-byte block and 3 bytes left, it's
			0x030303.  In the oddball case where nb is an exact multiple
			multiple of block_length, set the padval to blocksize (i.e.
			add one full block) */
		mut padval := byte((block_length - (nb % block_length)))
		padval = if padval == byte(0) { byte(block_length) } else { padval }

		to_append := []byte{len:int(padval), init:padval}
		(*buf) << to_append
		to_append.free()
	} else {
		/* We are UNPADDING this block (and removing bytes)
			We really just need to verify that the pad bytes are correct,
			so start at the end of the string and work backwards. */

		/* Figure out what the padlength should be by looking at the
			last byte */
		mut idx := nb - 1
		padval := buf[idx]

		/* padval must be nonzero and <= block length */
		if padval <= 0 || padval > block_length {
			panic('bad padval')
		}

		/* First byte's accounted for; do the rest */
		idx--

		for idx >= nb-padval {
			if buf[idx] != padval {
				panic('bad padval at $idx')
			}
			idx--
		}

		/* If we got here, the pad checked out, so return a smaller
			number of bytes than nb (basically where we left off+1) */
		s := (*buf)[..idx+1]
		(*buf) = s
	}
}

fn C.cbc_start() int
fn C.cbc_decrypt() int
fn C.cbc_encrypt() int

[typedef]
struct C.symmetric_CBC {}

pub fn cbc_decrypt_into(key, iv, @in []byte, mut out []byte) {
	cipher := C.find_cipher('aes')
	if cipher == -1 {
		panic('unable to find aes cipher')
	}

	cbc := C.symmetric_CBC{}

	mut res := C.cbc_start(cipher, iv.data, key.data, key.len, 0, &cbc)

	if res != 0 {
		panic('Unable to start cbc $res')
	}

	res = C.cbc_decrypt(@in.data, out.data, @in.len, &cbc)

	if res != 0 {
		panic('Unable to cbc decrypt $res')
	}

	// unpad
	pkcs7_pad(mut out, 16, false)
}

pub fn cbc_encrypt_into(key, iv []byte, mut @in []byte, mut out []byte) {
	cipher := C.find_cipher('aes')
	if cipher == -1 {
		panic('unable to find aes cipher')
	}

	cbc := C.symmetric_CBC{}

	mut res := C.cbc_start(cipher, iv.data, key.data, key.len, 0, &cbc)

	if res != 0 {
		panic('Unable to start cbc $res')
	}

	// pad
	pkcs7_pad(mut @in, 16, true)

	res = C.cbc_encrypt(@in.data, out.data, @in.len, &cbc)

	if res != 0 {
		panic('Unable to cbc encrypt $res')
	}
}