extern crate sgx_tseal;
extern crate sgx_types;
use self::sgx_tseal::SgxSealedData;
use sgx_types::marker::ContiguousMemory;
use keygen::BlockchainKeyStruct;

#[cfg(not(target_env = "sgx"))]
use sgx_types::{sgx_status_t, sgx_sealed_data_t};

// struct for random data
#[derive(Copy, Clone, Default, Debug)]
struct RandDataFixed {
    key: u32,
    rand: [u8; 16],
}

unsafe impl ContiguousMemory for RandDataFixed {}


#[no_mangle]
pub extern "C" fn seal_keypair(sealed_log: * mut u8, keypair: BlockchainKeyStruct) -> sgx_status_t {

    println!("Sealing keypair..."); 
    
    // empty additional text, ref: https://dingelish.github.io/sgx_tseal/sgx_tseal/struct.SgxSealedData.html
    let aad: [u8; 0] = [0_u8; 0];

    let result = SgxSealedData::<BlockchainKeyStruct>::seal_data(&aad, &keypair);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => { return ret; },
    };
    let sealed_log_size : u32 = 1024;
    let opt = to_sealed_log_for_fixed(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("Successfully sealed");

    sgx_status_t::SGX_SUCCESS

}

fn to_sealed_log_for_fixed<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}