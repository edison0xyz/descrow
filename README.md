# Data Escrow with Intel SGX

This repository consists of the following codebase:
* `tlsserver` : TLS Server to be executed by the Authority


### Installation instructions

This implementation is written in Rust using [Rust-SDK](https://github.com/apache/incubator-teaclave-sgx-sdk).

```bash
docker run -ti --rm -v /Users/edison/code/sgx/data-escrow:/root/sgx  baiduxlab/sgx-rust
```

From the root directory:
```bash
export SGX_MODE=SW
make
cd bin
./app 

## simulation mode 
SGX_MODE=SW make
```