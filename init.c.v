module tomcrypt

fn C.register_hash() int
fn C.register_prng() int 
fn C.register_cipher() int 

fn C.find_prng() int
fn C.find_hash() int
fn C.find_cipher() int

fn init() {
	if C.register_prng(&C.sprng_desc) == -1 {
		panic('Error registering sprng')
	}
	if C.register_hash(&C.sha1_desc) == -1 {
		panic('Error registering SHA1 hash')
	}
	if C.register_cipher(&C.aes_desc) == -1 {
		panic('Error registering aes cipher')
	}
	C.ltc_mp = C.ltm_desc
}