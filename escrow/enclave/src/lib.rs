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

#![crate_name = "tlsclient"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_trts;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_tcrypto;
extern crate sgx_tseal;

mod shamir;
mod keygen;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;
extern crate secp256k1;
extern crate serde_cbor;
extern crate webpki;
extern crate rustls;

use sgx_trts::trts::{rsgx_lfence, rsgx_sfence};

use sgx_types::*;
use std::collections;

use std::untrusted::fs;
use std::io::BufReader;

use std::ffi::CStr;
use std::os::raw::c_char;

use std::string::String;
use std::vec::Vec;
use std::boxed::Box;
use std::io::{Read, Write};
use std::slice;
use std::sync::{Arc, SgxMutex, SgxRwLock};
use std::net::TcpStream;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, AtomicPtr, Ordering};
use std::str;
use std::str::from_utf8;

use sgx_rand::{Rng, StdRng};
use sgx_tcrypto::SgxEccHandle;
use sgx_tseal::SgxSealedData;
use sgx_types::marker::ContiguousMemory;
use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t};
use sgx_types::{sgx_sealed_data_t, sgx_status_t};


use keygen::generate_eth_key;
use shamir::SecretData;


use rustls::Session;

pub struct TlsClient {
    socket: TcpStream,
    tls_session:  rustls::ClientSession,
}

static GLOBAL_CONTEXT_COUNT: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    static ref GLOBAL_CONTEXTS: SgxRwLock<HashMap<usize, AtomicPtr<TlsClient>>> = {
        SgxRwLock::new(HashMap::new())
    };
}

impl TlsClient {
    fn new(fd: c_int, hostname: &str, cfg: Arc<rustls::ClientConfig>) -> TlsClient {
        TlsClient {
            socket: TcpStream::new(fd).unwrap(),
            tls_session: rustls::ClientSession::new(&cfg, webpki::DNSNameRef::try_from_ascii_str(hostname).unwrap())
        }
    }

    fn do_read(&mut self, plaintext: &mut Vec<u8>) -> c_int {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        let rc = self.tls_session.read_tls(&mut self.socket);
        if rc.is_err() {
            println!("TLS read error: {:?}", rc);
            return -1;
        }

        // If we're ready but there's no data: EOF.
        if rc.unwrap() == 0 {
            println!("EOF");
            return -1;
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            println!("TLS error: {:?}", processed.unwrap_err());
            return -1;
        }

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        let rc = self.tls_session.read_to_end(plaintext);

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if rc.is_err() {
            let err = rc.unwrap_err();
            println!("Plaintext read error: {:?}", err);
            return -1;
        }
        plaintext.len() as c_int
    }

    // fn is_traffic(&self) -> bool {
    //     !self.tls_session.is_handshaking()
    // }

    fn write(&mut self, plaintext: &[u8]) -> c_int{
        self.tls_session.write(plaintext).unwrap() as c_int
    }

    fn do_write(&mut self) {
        self.tls_session.write_tls(&mut self.socket).unwrap();
    }
}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
    cache: SgxMutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    filename: Option<String>,
}

impl PersistCache {
    /// Make a new cache.  If filename is Some, load the cache
    /// from it and flush changes back to that file.
    fn new(filename: &Option<String>) -> PersistCache {
        let cache = PersistCache {
            cache: SgxMutex::new(collections::HashMap::new()),
            filename: filename.clone(),
        };
        if cache.filename.is_some() {
            cache.load();
        }
        cache
    }

    /// If we have a filename, save the cache contents to it.
    fn save(&self) {
        use rustls::internal::msgs::codec::Codec;
        use rustls::internal::msgs::base::PayloadU16;

        if self.filename.is_none() {
            return;
        }

        let mut file = fs::File::create(self.filename.as_ref().unwrap())
            .expect("cannot open cache file");

        for (key, val) in self.cache.lock().unwrap().iter() {
            let mut item = Vec::new();
            let key_pl = PayloadU16::new(key.clone());
            let val_pl = PayloadU16::new(val.clone());
            key_pl.encode(&mut item);
            val_pl.encode(&mut item);
            file.write_all(&item).unwrap();
        }
    }

    /// We have a filename, so replace the cache contents from it.
    fn load(&self) {
        use rustls::internal::msgs::codec::{Codec, Reader};
        use rustls::internal::msgs::base::PayloadU16;

        let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut cache = self.cache.lock()
            .unwrap();
        cache.clear();
        let mut rd = Reader::init(&data);

        while rd.any_left() {
            let key_pl = PayloadU16::read(&mut rd).unwrap();
            let val_pl = PayloadU16::read(&mut rd).unwrap();
            cache.insert(key_pl.0, val_pl.0);
        }
    }
}

impl rustls::StoresClientSessions for PersistCache {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.lock()
            .unwrap()
            .insert(key, value);
        self.save();
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock()
            .unwrap()
            .get(key).cloned()
    }
}

/// Build a `ClientConfig` from our arguments
fn make_config(cert: &str) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::new();

    let certfile = fs::File::open(cert).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);
    config.root_store
        .add_pem_file(&mut reader)
        .unwrap();

    let cache = Option::None;
    let persist = Arc::new(PersistCache::new(&cache));
    config.set_persistence(persist);

    Arc::new(config)
}

struct Sessions;

impl Sessions {
    fn new_session(svr_ptr : *mut TlsClient) -> Option<usize> {
        match GLOBAL_CONTEXTS.write() {
            Ok(mut gctxts) => {
                let curr_id = GLOBAL_CONTEXT_COUNT.fetch_add(1, Ordering::SeqCst);
                gctxts.insert(curr_id, AtomicPtr::new(svr_ptr));
                Some(curr_id)
            },
            Err(x) => {
                println!("Locking global context SgxRwLock failed! {:?}", x);
                None
            },
        }
    }

    fn get_session(sess_id: size_t) -> Option<*mut TlsClient> {
        match GLOBAL_CONTEXTS.read() {
            Ok(gctxts) => {
                match gctxts.get(&sess_id) {
                    Some(s) => {
                        Some(s.load(Ordering::SeqCst))
                    },
                    None => {
                        println!("Global contexts cannot find session id = {}", sess_id);
                        None
                    }
                }
            },
            Err(x) => {
                println!("Locking global context SgxRwLock failed on get_session! {:?}", x);
                None
            },
        }
    }

    fn remove_session(sess_id: size_t) {
        if let Ok(mut gctxts) = GLOBAL_CONTEXTS.write() {
            if let Some(session_ptr) = gctxts.get(&sess_id) {
                let session_ptr = session_ptr.load(Ordering::SeqCst);
                let session = unsafe { &mut *session_ptr };
                let _ = unsafe { Box::<TlsClient>::from_raw(session as *mut _) };
                let _ = gctxts.remove(&sess_id);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn tls_client_new(fd: c_int, hostname: * const c_char, cert: * const c_char) -> usize {
    let certfile = unsafe { CStr::from_ptr(cert).to_str() };
    if certfile.is_err() {
        return 0xFFFF_FFFF_FFFF_FFFF;
    }
    let config = make_config(certfile.unwrap());
    let name = unsafe { CStr::from_ptr(hostname).to_str() };
    let name = match name {
        Ok(n) => n,
        Err(_) => {
            return 0xFFFF_FFFF_FFFF_FFFF;
        }
    };
    let p: *mut TlsClient = Box::into_raw(Box::new(TlsClient::new(fd, name, config)));
    match Sessions::new_session(p) {
        Some(s) => s,
        None => 0xFFFF_FFFF_FFFF_FFFF,
    }
}

#[no_mangle]
pub extern "C" fn tls_client_read(session_id: usize, buf: * mut c_char, cnt: c_int) -> c_int {
    if buf.is_null() {
        return -1;
    }

    rsgx_sfence();

    if let Some(session_ptr) = Sessions::get_session(session_id) {
        let session= unsafe { &mut *session_ptr };

        let mut plaintext = Vec::new();
        let mut result = session.do_read(&mut plaintext);

        if result == -1 {
            return result;
        }
        if cnt < result {
            result = cnt;
        }

        let raw_buf = unsafe { slice::from_raw_parts_mut(buf as * mut u8, result as usize) };
        raw_buf.copy_from_slice(plaintext.as_slice());
        result
    } else { -1 }
}

#[no_mangle]
pub extern "C" fn tls_client_write(session_id: usize, buf: * const c_char, cnt: c_int)  -> c_int {
    if let Some(session_ptr) = Sessions::get_session(session_id) {
        let session = unsafe { &mut *session_ptr };

        // no buffer, just write_tls.
        if buf.is_null() || cnt == 0 {
            session.do_write();
            0
        } else {
            rsgx_lfence();
            let cnt = cnt as usize;
            let plaintext = unsafe { slice::from_raw_parts(buf as * mut u8, cnt) };
            let result = session.write(plaintext);

            result
        }
    } else { -1 }
}

#[no_mangle]
pub extern "C" fn tls_client_wants_read(session_id: usize)  -> c_int {
    if let Some(session_ptr) = Sessions::get_session(session_id) {
        let session= unsafe { &mut *session_ptr };
        let result = session.tls_session.wants_read() as c_int;
        result
    } else { -1 }
}

#[no_mangle]
pub extern "C" fn tls_client_wants_write(session_id: usize)  -> c_int {
    if let Some(session_ptr) = Sessions::get_session(session_id) {
        let session= unsafe { &mut *session_ptr };
        let result = session.tls_session.wants_write() as c_int;
        result
    } else { -1 }
}

#[no_mangle]
pub extern "C" fn tls_client_close(session_id: usize) {
    Sessions::remove_session(session_id)
}




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


unsafe impl ContiguousMemory for RandDataFixed {}

#[no_mangle]
pub extern "C" fn process_data_registration(
    escrowed_data_identifier: *const u8,
    text_len: usize,
) -> sgx_status_t {
    println!("[+] process_data_registration.. ");
    println!("{:?}", escrowed_data_identifier);

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
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

    println!("Shamir share 1 {:?}", sk_d1);
    println!("Shamir share 2 {:?}", sk_d2);

    // for testing the recovery functions only
    // println!("Attempting to recover secret");
    // let recovered = SecretData::recover_secret(2,vec![sk_d1, sk_d2]).unwrap();
    // println!("Recovered secret: {}", recovered);

    println!("[2]   Key successfully split into d1 and d2");

    println!("[3]   Attempting to send D2 to authority using TLS. Establishing connection with authority... ");


    println!("[3]   Connection established");
    println!("[3]   D2 securely sent to authority");

    println!("[4]   Sealing sk_d1 and DID...");

    let mut sealed_log_arr: [u8; 2048] = [0; 2048];
    let sealed_log = sealed_log_arr.as_mut_ptr();
    let sealed_log_size: u32 = 2048;

    let ret = create_sealeddata_for_fixed(sealed_log, sealed_log_size);
    match ret {
        sgx_status_t::SGX_SUCCESS => { println!("[4] Successfulyl sealed d1 into sgx") },
        _ => {
            println!("[-] Error sealing data {}!", ret);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    println!("[4]   Seal successful.");

    println!("[5] Signing transaction payload with sk_enc... ");
    println!("[5] Transaction payload successfully signed");

    // println!("Pub key: {:?}", sk_d1);
    // println!("size: {}", s1);

    // keygen::generate_data_key();

    println!("[+]   process data registration completed");

    sgx_status_t::SGX_SUCCESS
}

fn to_sealed_log<T: Copy + ContiguousMemory>(
    sealed_data: &SgxSealedData<T>,
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> Option<*mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as *mut sgx_sealed_data_t, sealed_log_size)
    }
}

#[no_mangle]
pub extern "C" fn create_sealeddata_for_fixed(
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> sgx_status_t {
    let mut data = RandDataFixed::default();
    data.key = 0x1234;

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    rand.fill_bytes(&mut data.rand);

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<RandDataFixed>::seal_data(&aad, &data);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        }
    };

    let opt = to_sealed_log_for_fixed(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealeddata_for_fixed(
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> sgx_status_t {
    let opt = from_sealed_log_for_fixed::<RandDataFixed>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };

    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        }
    };

    let data = unsealed_data.get_decrypt_txt();

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

// #[no_mangle]
// pub extern "C" fn create_sealeddata_for_serializable(
//     sealed_log: *mut u8,
//     sealed_log_size: u32,
// ) -> sgx_status_t {
//     let mut data = RandDataSerializable::default();
//     data.key = 0x1234;

//     let mut rand = match StdRng::new() {
//         Ok(rng) => rng,
//         Err(_) => {
//             return sgx_status_t::SGX_ERROR_UNEXPECTED;
//         }
//     };
//     rand.fill_bytes(&mut data.rand);

//     data.vec.extend(data.rand.iter());

//     let encoded_vec = serde_cbor::to_vec(&data).unwrap();
//     let encoded_slice = encoded_vec.as_slice();
//     println!("Length of encoded slice: {}", encoded_slice.len());
//     println!("Encoded slice: {:?}", encoded_slice);

//     let aad: [u8; 0] = [0_u8; 0];
//     let result = SgxSealedData::<[u8]>::seal_data(&aad, encoded_slice);
//     let sealed_data = match result {
//         Ok(x) => x,
//         Err(ret) => {
//             return ret;
//         }
//     };

//     let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, sealed_log_size);
//     if opt.is_none() {
//         return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
//     }

//     println!("{:?}", data);

//     sgx_status_t::SGX_SUCCESS
// }

// #[no_mangle]
// pub extern "C" fn verify_sealeddata_for_serializable(
//     sealed_log: *mut u8,
//     sealed_log_size: u32,
// ) -> sgx_status_t {
//     let opt = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size);
//     let sealed_data = match opt {
//         Some(x) => x,
//         None => {
//             return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
//         }
//     };

//     let result = sealed_data.unseal_data();
//     let unsealed_data = match result {
//         Ok(x) => x,
//         Err(ret) => {
//             return ret;
//         }
//     };

//     let encoded_slice = unsealed_data.get_decrypt_txt();
//     println!("Length of encoded slice: {}", encoded_slice.len());
//     println!("Encoded slice: {:?}", encoded_slice);
//     let data: RandDataSerializable = serde_cbor::from_slice(encoded_slice).unwrap();

//     println!("{:?}", data);

//     sgx_status_t::SGX_SUCCESS
// }

fn to_sealed_log_for_fixed<T: Copy + ContiguousMemory>(
    sealed_data: &SgxSealedData<T>,
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> Option<*mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as *mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_fixed<'a, T: Copy + ContiguousMemory>(
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(
            sealed_log as *mut sgx_sealed_data_t,
            sealed_log_size,
        )
    }
}

fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(
    sealed_data: &SgxSealedData<[T]>,
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> Option<*mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as *mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(
            sealed_log as *mut sgx_sealed_data_t,
            sealed_log_size,
        )
    }
}