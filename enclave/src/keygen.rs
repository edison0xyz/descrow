use std::slice;
use std::vec::Vec;

use secp256k1::SecretKey;
use sgx_rand::{thread_rng, Rng};
use sgx_tcrypto::*;
use sgx_trts::memeq::ConsttimeMemEq;
use sgx_types::marker::ContiguousMemory;
use sgx_types::sgx_status_t;

// fixme: secret key should only be private within crate
#[derive(Copy, Clone)]
pub struct BlockchainKeyStruct {
    pub secret_key: [u8; 32],
}

// contiguous memory required for sealed_data function
unsafe impl ContiguousMemory for BlockchainKeyStruct {}

pub extern "C" fn generate_private_key() -> SecretKey {
    SecretKey::parse(&get_randombytes_32_u8()).unwrap()
}

// get random 32 bytes u8 array
fn get_randombytes_32_u8() -> [u8; 32] {
    let mut arr = [0; 32];
    arr.copy_from_slice(&get_x_random_bytes_vec(32));
    arr
}

pub fn get_x_random_bytes_vec(len: usize) -> Vec<u8> {
    let mut x = vec![0u8; len];
    thread_rng().fill_bytes(&mut x);
    x
}

// generate data key from DID
#[no_mangle]
pub extern "C" fn generate_data_key(text: *const u8, text_len: usize) -> sgx_status_t {
    let text_slice = unsafe { slice::from_raw_parts(text, text_len) };

    if text_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let mod_size: i32 = 256;
    let exp_size: i32 = 4;
    let mut n: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut d: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut e: Vec<u8> = vec![1, 0, 1, 0];
    let mut p: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut q: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; mod_size as usize / 2];

    let result = rsgx_create_rsa_key_pair(
        mod_size,
        exp_size,
        n.as_mut_slice(),
        d.as_mut_slice(),
        e.as_mut_slice(),
        p.as_mut_slice(),
        q.as_mut_slice(),
        dmp1.as_mut_slice(),
        dmq1.as_mut_slice(),
        iqmp.as_mut_slice(),
    );

    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {}
    }

    let privkey = SgxRsaPrivKey::new();
    let pubkey = SgxRsaPubKey::new();

    let result = pubkey.create(mod_size, exp_size, n.as_slice(), e.as_slice());
    match result {
        Err(x) => return x,
        Ok(()) => {}
    };

    let result = privkey.create(
        mod_size,
        exp_size,
        e.as_slice(),
        p.as_slice(),
        q.as_slice(),
        dmp1.as_slice(),
        dmq1.as_slice(),
        iqmp.as_slice(),
    );
    match result {
        Err(x) => return x,
        Ok(()) => {}
    };

    let mut ciphertext: Vec<u8> = vec![0_u8; 256];
    let mut chipertext_len: usize = ciphertext.len();
    let ret = pubkey.encrypt_sha256(ciphertext.as_mut_slice(), &mut chipertext_len, text_slice);
    match ret {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            println!("rsa chipertext_len: {:?}", chipertext_len);
        }
    };



    let mut plaintext: Vec<u8> = vec![0_u8; 256];
    let mut plaintext_len: usize = plaintext.len();
    let ret = privkey.decrypt_sha256(
        plaintext.as_mut_slice(),
        &mut plaintext_len,
        ciphertext.as_slice(),
    );
    match ret {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            println!("rsa plaintext_len: {:?}", plaintext_len);
        }
    };

    if plaintext[..plaintext_len].consttime_memeq(text_slice) == false {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    sgx_status_t::SGX_SUCCESS
}
