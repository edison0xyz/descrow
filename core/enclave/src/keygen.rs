use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t};
use sgx_tcrypto::{SgxEccHandle};

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