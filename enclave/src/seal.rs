extern crate sgx_tseal;
extern crate sgx_types;
use sgx_rand::{Rng, StdRng};
use self::sgx_tseal::SgxSealedData;
use sgx_types::marker::ContiguousMemory;
use error::EnclaveError;

#[cfg(not(target_env = "sgx"))]
use sgx_types::{sgx_status_t, sgx_sealed_data_t};

// struct for random data
#[derive(Copy, Clone, Default, Debug)]
struct RandDataFixed {
    key: u32,
    rand: [u8; 16],
}

unsafe impl ContiguousMemory for RandDataFixed {}


// create sealed data for fixed size
#[no_mangle]
pub extern "C" fn seal_data(sealed_log_size: u32) -> sgx_status_t {
    let mut data = RandDataFixed::default();
    data.key = 0x1234;

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    rand.fill_bytes(&mut data.rand);

    // // additional data
    // let aad: [u8; 0] = [0_u8; 0];
    // let result = SgxSealedData::<RandDataFixed>::seal_data(&aad, &data);
    
    
    // let sealed_data = match result {
    //   Ok(x) => x,
    //   Err(ret) => { 
    //     println!("Error..");
    //     return ret; 
    //   },
    // };


    // let sealed_res = to_sealed_log(&sealed_data, sealed_log, sealed_log_size);
    // if sealed_res.is_none() {
    //   return sgx_status_t::SGX_ERROR_UNEXPECTED;
    // }

    println!("{:?}", data);

    println!("Sealing complete.");

    sgx_status_t::SGX_SUCCESS
}


fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
  unsafe {
      sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
  }
}