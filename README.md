# Data Escrow with Intel SGX

This repository contains the supplementary files for the data escrow project. It assumes a connection from the blockchain, which will trigger the functions within this repo. 

This project focuses on implementing secure functions to enable data escrow capability with Intel SGX. We have support for key splits, ethereum keygen, key seal and codebases for TLS CLient and Server within this repositoty.

This repository consists of the following codebase:
* `core`: core services for the main data escrow functions (main codebase)
* `tlsserver` : TLS Server to be executed by the Authority
* `tlsclient` : TLSCLient to be used in the data registration

There are known SDK issues which has been reported in [sgx-sdk #224](https://github.com/apache/incubator-teaclave-sgx-sdk/issues/226), [sgx-sdk #220](https://github.com/apache/incubator-teaclave-sgx-sdk/issues/220), and [#221](https://github.com/apache/incubator-teaclave-sgx-sdk/issues/221). This happened due to an incompatible upgrade of the intel sgx sdk, and the maintainers are fixing the issue.

Since there were issues building the files, the code for `tlsclient` has been moved to a different subfolder temporarily. The codebase should be able to be built independently. Once the issue is fixed, the `tlsclient` can be merged into `core` codebase.

## Installation Requirements

This implementation is written in Rust using [Rust-SDK](https://github.com/apache/incubator-teaclave-sgx-sdk).

System requirement:
* Ubuntu 16.04 or 18.04
* Intel SGX SDK 2.9.1 for Linux installed
* Docker (Recommended)

It is recommended to use the docker for building this project. The docker images support both hardware SGX mode and software simulator mode. Users with macbook has to run the code with the software simulator mode enabled.

## Configuration

The code comes with docker files for building the project easily. Developers can choose to execute the code through hardware mode and software mode. Software mode uses Intel SGX simulator mode, and is the only way that Mac users and developers without access to intel sgx hardware chip could run the code.

### Software Mode (Docker)

Run the following command:

```bash
docker run -ti --rm -p 8443:8443 -v /path/to/data-escrow:/root/sgx  baiduxlab/sgx-rust
cd sgx
export SGX_MODE=SW
```

The `Makefile` sets the `SGX_MODE=HW` by default, so failure to change the config through environment variable will result in an error. If you face the following issue, please type `export SGX_MODE=SW`.

```
Info: Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards.
Error: Invalid SGX device.

```



The `-p 8443:8443` specifies the port mapping required for TLS communication. Refer to [docker networking](https://docs.docker.com/network/) for more information.



### Hardware Mode

Hardware mode only works for host machine with intel SGX chips. Users have to enable the Intel SGX through BIOS and install the [Intel SGX SDK for Linux](https://github.com/intel/linux-sgx). 

Once the SDK is enabled, the folder `/dev/isgx` should appear. To start a docker with hardware support, add a `--device /dev/isgx` flag to the `docker run` command. 

```bash
docker run -ti --device /dev/isgx --rm -p 8443:8443 -v /path/to/data-escrow:/root/sgx  baiduxlab/sgx-rust
cd sgx
```


## Running the code

For all projects, change directory into the root folder and run the following command:

```
make clean; make
cd bin
./app
```

### Running TLSServer and TLSClient

Ensure that the TLSClient and TLSServer are run with the `-p` configured to map container ports to host port. Example, if your TLSServer uses port 8443, add the flag `-p 8443:8443` to the docker image. 

To change to a custom port, make the edits into the source code, build the files and run a docker image with the mapping to the correct port.

```bash
# running the tlsserver
cd sgx/tlsserver/bin
./app

# client
cd sgx/tlsclient/bin
./app
```

## Utilities

### Basics to Rust and IntelSGX

ECalls and OCalls definition are specified in a `*.edl` file. For fixed-length array in ECALL/OCALL definition, declare it as an array. For dynamic-length array, use the keyword size= to let the Intel SGX knows how many bytes should be copied.

ECalls must be accompanied by a `#[no_mangle]` flag. 

If a Rust SDK is preceded with `unsafe`, it means we are explicitly telling the compiler to ignore the memory leak guarantees of rust so we can perform functions that the compiler is unable to do memory check on (e.g. enclave functions). If an enclave function is not preceded with an `unsafe` keyword, rust compiler will not build the file as the compiler won't be able to access the memory space of the intel sgx during compile time.

### Docker networking

Getting IP address from the docker.

```bash
docker inspect silly_hellman | grep IPAddress
```


## Acknowledgements

Intel SGX Rust SDK: [https://github.com/apache/incubator-teaclave-sgx-sdk](https://github.com/apache/incubator-teaclave-sgx-sdk)
