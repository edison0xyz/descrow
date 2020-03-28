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
extern crate sgx_tservice;

mod seal;
mod keygen;
mod error;

use sgx_types::*;
use std::io::{self, Write};
use std::slice;
use std::string::String;
use std::vec::Vec;

use seal::seal_data;
use keygen::generate_private_key;
use sgx_rand::{thread_rng, Rng};

use secp256k1::{PublicKey, SecretKey};

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

#[no_mangle]
pub extern "C" fn generate_keys() -> sgx_status_t {
    println!("generating keys...");

    // generate randomness using sgx_rand
    let mut v = [0u8; 32];
    thread_rng().fill_bytes(&mut v);

    let seckey = SecretKey::parse(&v).unwrap();
    let pubkey = PublicKey::from_secret_key(&seckey);

    // let pk = pubkey.serialize();
    println!("Secret key: {:?}", seckey);

    println!("Public key: {:?}", pubkey);

    println!("Key generated");

    let sealed_log_size : u32 = 1024;
    let ret_status = seal_data(sealed_log_size);

    match ret_status {
        sgx_status_t::SGX_SUCCESS => println!("Success"), 
        _ => println!("Error"),
    }

    // let mut msg = [0u8; 32];
    // thread_rng().fill_bytes(&mut msg);

    // SecretKey::random(&mut thread_rng());

    // let x = sgx_rand::random::<u8>();
    // println!("{}", x);

    sgx_status_t::SGX_SUCCESS
}
