# Escrow Vault using SGX




### Installation instructions

This implementation is written in Rust using [Rust-SDK](https://github.com/apache/incubator-teaclave-sgx-sdk).


```bash
docker run -ti --rm -v /Users/edison/code/sgx/incubator-teaclave-sgx-sdk:/root/sgx  baiduxlab/sgx-rust
```

From the root directory:
```bash
make
cd bin
./app 

## simulation mode 
SGX_MODE=SW make
```