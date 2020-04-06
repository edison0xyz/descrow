# Complains about Intel SGX

Complains about intel SGX goes here...


## Compatibility with third-party libaries

Although IntelSGX comes with some standard libraries that are available for us, it lacks an ecosystem of good components that we can reuse.

We chose rust SDK because the maintainers has modified some existing libraries. Credits:
* Rust TLS library modified for IntelSGX: https://github.com/mesalock-linux/rustls


## Rewriting of Shamir library

Shamir is not an in-built function of IntelSGX, and therefore we have to port over the library ourselves. Porting a crypto library involves changes to some parts of the code, including ensuring a fixed-length allocation and IntelSGX compatible `Rng` functions using the `sgx_rand` library.

