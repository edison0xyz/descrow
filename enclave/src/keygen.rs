use std::result;
use std::vec::Vec;
use sgx_rand::{Rng, thread_rng};
use secp256k1::{PublicKey, SecretKey};
use error::EnclaveError;

type Result<T> = result::Result<T, EnclaveError>;

pub extern "C" fn generate_private_key() -> SecretKey {
  SecretKey::parse(&get_randombytes_32_u8()).unwrap()
}

// get random 32 bytes u8 array
fn get_randombytes_32_u8() -> [u8; 32] {
  let mut arr = [0; 32];
  arr.copy_from_slice(&get_x_random_bytes_vec(32));
  arr
}

fn get_x_random_bytes_vec(len: usize) -> Vec<u8> {
  let mut x = vec![0u8; len]; 
  thread_rng().fill_bytes(&mut x);
  x
}