# Data Escrow with Intel SGX

This repository consists of the following codebase:
* `tlsserver` : TLS Server to be executed by the Authority
* `tlsclient` : TLSCLient to be used in the data registration
* `core`: core services for initiating wallet creation using `secp256k1`


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

### Utilities

Getting IP address from the docker.

```bash
docker inspect silly_hellman | grep IPAddress
```