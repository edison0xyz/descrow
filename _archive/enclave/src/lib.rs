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
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate secp256k1;
extern crate serde_cbor;
extern crate serde_derive;
extern crate sgx_rand;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tseal;

mod keygen;
mod seal;
mod tss;

use sgx_types::*;
use std::io::{self, Write};
use std::slice;
use std::string::String;
use std::vec::Vec;
use tss::SecretData;

use keygen::{generate_data_key, generate_private_key, BlockchainKeyStruct};
use seal::seal_keypair;

/// A function simply invokes ocall print to print the incoming string
///
/// # Parameters
///
/// **some_string**
///
/// A pointer to the string to be printed
///
/// **len**
///
/// An unsigned int indicates the length of str
///
/// # Return value
///
/// Always returns SGX_SUCCESS
#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a ";
    // An array
    let word: [u8; 4] = [82, 117, 115, 116];
    // An vector
    let word_vec: Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8").as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    sgx_status_t::SGX_SUCCESS
}

// main utility for generate keys function. Generates and seal the key
#[no_mangle]
pub extern "C" fn generate_keys() -> sgx_status_t {
    println!("[+] Generating keys...");

    let sk = generate_private_key().serialize();
    let new_key: BlockchainKeyStruct = BlockchainKeyStruct { secret_key: sk };

    println!("[+] Key generated");
    println!("{:?}", sk);

    // seal keystruct into enclave
    let sealed_log: &mut u8 = &mut 0_u8;
    let result = seal_keypair(sealed_log, new_key);
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] Successfully generated and sealed keys.");
            sgx_status_t::SGX_SUCCESS
        }
        _ => {
            println!("[-] Error generating and sealing keys.");
            sgx_status_t::SGX_ERROR_INVALID_PARAMETER
        }
    }
}

#[no_mangle]
pub extern "C" fn process_data_registration(text: *const u8, text_len: usize) -> sgx_status_t {
    println!("[+] process_data_registration.. ");

    generate_data_key(text, text_len);

    // test shamir
    // println!("Testing shamir...");
    // let seret_data = SecretData::with_secret("Hello", 3);

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn shamir_split_keys() -> sgx_status_t {
    println!("[+] test_shamir ");

    // test shamir
    println!("Testing shamir...");
    let secret_data = SecretData::with_secret("Add secret key here", 2);
    let share_1 = secret_data.get_share(1).unwrap();
    let share_2 = secret_data.get_share(2).unwrap();

    println!("Shamir share 1 {:?}", share_1);
    println!("Shamir share 2 {:?}", share_2);


    let test_recovery = SecretData::recover_secret(2, vec![share_1, share_2]).unwrap();
    println!("Recovered secret: {}", test_recovery);

    sgx_status_t::SGX_SUCCESS
}

