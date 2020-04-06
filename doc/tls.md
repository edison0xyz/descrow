# SSL/TLS Handshake process

* Server has a `cert` and a `publicKey`
* Whenever a client wants to initiate a connection, 

## TLSServer

In our TLS server, we have the following:

```rust
struct TlsServer {
    enclave_id: sgx_enclave_id_t,
    server: TcpListener,
    cert: CString,
    key: CString,
    mode: ServerMode,
    connections: HashMap<mio::Token, Connection>,
    next_id: usize,
}
```
This code binds together a TCP listening socket and an outstanding connection. 


If it is successful, it will return the following output:
```
root@cd6c23a03efe:~/sgx/tlsserver/bin# ./app
[+] Init Enclave Successful 45805826211842!
[+] Tls client established in enclave
[+] TlsServer new "end.fullchain" "end.rsa"
[+] TlsServer new success!
```


## TLS Client

The TLSClient contains the following:
```rust
struct TlsClient {
    enclave_id: sgx_enclave_id_t,
    socket: TcpStream,
    closing: bool,
    tlsclient_id: usize,
}
```

On the `TLSClient`, we declared the following trusted functions (ECALL):

```c
public size_t tls_client_new(int fd, [in, string]char* hostname, [in, string] char* cert);
public int tls_client_read(size_t session_id, [out, size=cnt] char* buf, int cnt);
public int tls_client_write(size_t session_id, [in, size=cnt] char* buf, int cnt);
public int tls_client_wants_read(size_t session_id);
public int tls_client_wants_write(size_t session_id);
public void tls_client_close(size_t session_id);
```

Whenever we try to set up a new connection, the client first initiates iteself:

```rust
fn new(enclave_id: sgx_enclave_id_t, sock: TcpStream, hostname: &str, cert: &str) -> Option<TlsClient> {

      println!("[+] TlsClient new {} {}", hostname, cert);

      let mut tlsclient_id: usize = 0xFFFF_FFFF_FFFF_FFFF;
      let c_host = CString::new(hostname.to_string()).unwrap();
      let c_cert = CString::new(cert.to_string()).unwrap();

      let retval = unsafe {
          tls_client_new(enclave_id,
                          &mut tlsclient_id,
                          sock.as_raw_fd(),
                          c_host.as_ptr() as *const c_char,
                          c_cert.as_ptr() as *const c_char)
      };

      if retval != sgx_status_t::SGX_SUCCESS {
          println!("[-] ECALL Enclave [tls_client_new] Failed {}!", retval);
          return Option::None;
      }

      if tlsclient_id == 0xFFFF_FFFF_FFFF_FFFF {
          println!("[-] New enclave tlsclient error");
          return Option::None;
      }

      Option::Some(
          TlsClient {
          enclave_id: enclave_id,
          socket: sock,
          closing: false,
          tlsclient_id: tlsclient_id,
      })
  }

```

which calls the following trusted function within the enclave:

```rust
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

```

The trusted function first retrieves the `certfile` and `hostname` and instantiates a `name`, Then, it allocates a memory on the heap by using the `Box` function for the TLSClient. Once allocated successfully, the `client` attempts to initiate a new session:
```rust
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
```

The instantiating of the `new_session` from here onwards is completed with a `rustls` library, which performs the following step to establish a master secret

```rust
pub fn new(randoms: &SessionRandoms,
            hashalg: &'static ring::digest::Algorithm,
            pms: &[u8])
            -> SessionSecrets {
    let mut ret = SessionSecrets {
        randoms: randoms.clone(),
        hash: hashalg,
        master_secret: [0u8; 48],
    };

    let randoms = join_randoms(&ret.randoms.client, &ret.randoms.server);
    prf::prf(&mut ret.master_secret,
              ret.hash,
              pms,
              b"master secret",
              &randoms);
    ret
}
```

The `master_secret` generated here is based on random values generated during the `pre-master` phase. The `master_secret`, which is 48-bytes in length will be used by both the client and server to symmetrically encrypt the data.




When a client wants to send data, they will parse the data as a buffer of `const c_char` type:

```rust
#[no_mangle]
pub extern "C" fn tls_server_write(session_id: usize, buf: * const c_char, cnt: c_int)  -> c_int {
    if let Some(session_ptr) = Sessions::get_session(session_id) {
        let session = unsafe { &mut *(session_ptr) };

        // no buffer, just write_tls.
        if buf.is_null() || cnt == 0 {
            session.do_write();
            return 0;
        }

        rsgx_lfence();
        // cache buffer, waitting for next write_tls
        let cnt = cnt as usize;
        let plaintext = unsafe { slice::from_raw_parts(buf as * mut u8, cnt) };
        let result = session.write(plaintext);

        result
    } else { -1 }
}

```

An important point to note about `rust` is the use of `unsafe` function. The [rust handbook](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html) has adequately covered the subject of why `unsafe` functions are necessary. In our implementation, as static analysis is difficult and underlying computer hardware is inherently unsafe, declaring `unsafe` relaxes the compiler checks and allows us to do low-level programming with Intel SGX enclave. 



##### Closing connection

Once completed, the client will close the session using the following method:

```rust
fn close(&self) {

    let retval = unsafe {
        tls_client_close(self.enclave_id, self.tlsclient_id)
    };

    if retval != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave [tls_client_close] Failed {}!", retval);
    }
}
```
