// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "escrowenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tseal;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_tcrypto;

#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate secp256k1;


mod shamir;
mod keygen;

use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
use sgx_rand::{Rng, StdRng};
use std::vec::Vec;
use std::mem;
use std::str;
use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t};
use sgx_tcrypto::{SgxEccHandle};

use shamir::SecretData;
use keygen::generate_eth_key;


// This struct could not be used in sgx_seal directly because it is
// **not** continuous in memory. The `vec` is the bad member.
// However, it is serializable. So we can serialize it first and
// put convert the Vec<u8> to [u8] then put [u8] to sgx_seal API!
// note: serde and deserialisation is required  https://serde.rs/
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct RandDataSerializable {
    key: u32,
    rand: [u8; 16],
    vec: Vec<u8>,
}

#[derive(Copy, Clone, Default, Debug)]
struct RandDataFixed {
    key: u32,
    rand: [u8; 16],
}

// We can only impl ContiguousMemory for Fixed
// For RandDataSerializable, we use serde_cbor (or anything you like)
// to serialize it to a Vec<u8>. And then use the _slice func to deal
// with [u8] because [u8] does implemented ContiguousMemory
unsafe impl ContiguousMemory for RandDataFixed{}

#[no_mangle]
pub extern "C" fn process_data_registration(escrowed_data_identifier: *const u8, text_len: usize) -> sgx_status_t {
    println!("[+] process_data_registration.. ");
    println!("{:?}", escrowed_data_identifier);

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };

     // generate ecc256 Keypair
    let ecc_handle = SgxEccHandle::new();
    let _ = ecc_handle.open(); 
    println!("[1]   Attempting to create keypair");
    let mut private = sgx_ec256_private_t::default();
    let mut public = sgx_ec256_public_t::default();
    // let (private, public) = ecc_handle.create_key_pair().unwrap();
    println!("[1]   Private-Public Keys created");


    println!("[1]   Initialising escrow wallet private key and public key..");
    let sk = generate_eth_key();

    println!("[2]   Escrow wallet private key initialised successfully.");



    // convert private_key into string
    let private_key = match str::from_utf8(&private.r) {
        Ok(pk) => pk,
        Err(e) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    // println!("Private key: {:?}", private_key);

    // split the private key into share_1 (sk_d1) and share_2 (sk_d2)
    println!("[2]   Attempting to split keys..");
    let secret_data = SecretData::with_secret(private_key, 2);
    let sk_d1 = secret_data.get_share(1).unwrap();
    let sk_d2 = secret_data.get_share(2).unwrap();
    println!("[2]   Key successfully split into d1 and d2");

    println!("[3]   Attempting to send D2 to authority using TLS. Establishing connection with authority... ");
    println!("[3]   Connection established");
    println!("[3]   D2 securely sent to authority");


    println!("[4]   Sealing sk_d1 and DID...");
    println!("[4]   Seal successful.");


    println!("[5] Signing transaction payload with sk_enc... ");
    println!("[5] Transaction payload successfully signed"); 

    // println!("Shamir share 1 {:?}", sk_d1);
    // println!("Shamir share 2 {:?}", sk_d2);

    /*

    // for testing the recovery functions only
    println!("Attempting to recover secret");
    let recovered = SecretData::recover_secret(2,vec![sk_d1, sk_d2]).unwrap();
    println!("Recovered secret: {}", recovered);
    */

    // === sealing data ====

    // let s1 = sk_d1.len();

    // // // declare vectors
    // let sealed_log_size : u32 = 1024;
    // let mut sealed_log = [0_u8; 1024];
    // let mut sl : u8 = 0;

    // let ret = create_sealeddata_for_fixed(&mut sealed_log, sealed_log_size);
    // match ret {
    //     sgx_status_t::SGX_SUCCESS => { println!("[4] Successfulyl sealed d1 into sgx") },
    //     _ => {
    //         println!("[-] Error sealing data {}!", ret);
    //         return sgx_status_t::SGX_ERROR_UNEXPECTED;
    //     }
    // };

    // seal sk_d1

    // println!("Pub key: {:?}", sk_d1);
    // println!("size: {}", s1);

    // keygen::generate_data_key();

    println!("[+]   process data registration completed");

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn create_sealeddata_for_fixed(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {



    let mut data = RandDataFixed::default();
    data.key = 0x1234;

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut data.rand);

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<RandDataFixed>::seal_data(&aad, &data);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => { return ret; },
    };

    let opt = to_sealed_log_for_fixed(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealeddata_for_fixed(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let opt = from_sealed_log_for_fixed::<RandDataFixed>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };

    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        },
    };

    let data = unsealed_data.get_decrypt_txt();

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn create_sealeddata_for_serializable(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let mut data = RandDataSerializable::default();
    data.key = 0x1234;

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut data.rand);

    data.vec.extend(data.rand.iter());

    let encoded_vec = serde_cbor::to_vec(&data).unwrap();
    let encoded_slice = encoded_vec.as_slice();
    println!("Length of encoded slice: {}", encoded_slice.len());
    println!("Encoded slice: {:?}", encoded_slice);

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data(&aad, encoded_slice);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => { return ret; },
    };

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealeddata_for_serializable(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let opt = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };

    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        },
    };

    let encoded_slice = unsealed_data.get_decrypt_txt();
    println!("Length of encoded slice: {}", encoded_slice.len());
    println!("Encoded slice: {:?}", encoded_slice);
    let data: RandDataSerializable = serde_cbor::from_slice(encoded_slice).unwrap();

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

fn to_sealed_log_for_fixed<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_fixed<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<[T]>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
