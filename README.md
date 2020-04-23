# Data Escrow with Intel SGX

This repository consists of the following codebase:
* `tlsserver` : TLS Server to be executed by the Authority
* `tlsclient` : TLSCLient to be used in the data registration
* `core`: core services for initiating wallet creation using `secp256k1`


## Installation instructions

This implementation is written in Rust using [Rust-SDK](https://github.com/apache/incubator-teaclave-sgx-sdk).


### TLS Server

TLSServer will be operated by the authority. For this implementation, we provided a listening port for the TLSServer.

Run the following command. The TLSServer will be exposed through port 8443 (port number is customisable).

```bash
docker run -ti --rm -p 8443:8443 -v /Users/edison/code/sgx/data-escrow:/root/sgx baiduxlab/sgx-rust
```

### Data Escrow

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


Running

```bash
# running the tlsserver
cd sgx/tlsserver/bin
./app

# client
cd sgx/core/bin
./app
```

### Utilities

Getting IP address from the docker.

```bash
docker inspect silly_hellman | grep IPAddress
```