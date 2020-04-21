use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t};
use sgx_tcrypto::{SgxEccHandle};
use sgx_rand::{Rng, thread_rng};
use std::vec::Vec;
use secp256k1::SecretKey;
use sgx_rand::os::SgxRng;

pub fn generate_data_key() { 
  println!("[keygen]  generating data key");

  // generate using ecc
  let mut private = sgx_ec256_private_t::default();
  let mut public = sgx_ec256_public_t::default();

  // generate ecc256 Keypair
  let ecc_handle = SgxEccHandle::new();
  let (private_key, public_key) = ecc_handle.create_key_pair().unwrap();

  println!("keys generated.");
}



// generate ethereum private key using secp256k1
pub fn generate_eth_key() -> SecretKey {

  println!("[keygen.rs]   generating ethereum private key using secp256k1");
  let sk = SecretKey::default();
  sk
  // let mut rng = SgxRng::new().unwrap();
  // let sk = secp256k1::SecretKey::random(&mut rng).unwrap();

}


fn get_x_random_bytes_vec(len: usize) -> Vec<u8> {
  let mut x = vec![0u8; len]; 
  thread_rng().fill_bytes(&mut x);
  x
}
