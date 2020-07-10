module tomcrypt

struct C.Rsa_key {}

struct RsaKey {
	key C.Rsa_key
}

fn C.rsa_import() int

pub fn load_rsa_key(k []byte) RsaKey {
	r := RsaKey {}
	res := C.rsa_import(k.data, k.len, &r.key)
	if res != 0 {
		panic('unable to import key $res')
	}

	return r
}

fn C.rsa_encrypt_key() int

pub fn (key RsaKey) sha1_encrypt_key_into(@in []byte, mut out []byte) {
	hash_idx := C.find_hash('sha1')
	prng_idx := C.find_prng("sprng")

	size := out.len

	res := C.rsa_encrypt_key(
		@in.data,
		@in.len,
		out.data,
		&size,
		C.NULL,
		0,
		C.NULL,
		prng_idx,
		hash_idx,
		&key.key
	)

	if res != 0 {
		panic('unable to encrypt @in $res')
	}
}


pub fn (key RsaKey) sha1_encrypt_key(@in []byte) []byte {
	out := []byte{len:@in.len*16}

	key.sha1_encrypt_key_into(@in, mut out)

	return out
}