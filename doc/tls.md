# SSL/TLS Handshake process

* Server has a `cert` and a `publicKey`
* Whenever a client wants to initiate a connection, 

## TLSServer

In our TLS server, we have the following:

```rust
struct TlsServer {
  server: TcpListener,
    enclave_id: sgx_enclave_id_t,
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

#### Initialising a new TLS server

1. TLSServer's `main.rs` function initialises a new enclave:

```rust
fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}
```

2. The server sets up a few configurations like the certificate, key and a monitoring service for TcpStream. We use `poll` to monitor a large number of event types, until one of them is ready for `READ` or `WRITE`. 

```rust
let mut poll = mio::Poll::new().unwrap();
poll.register(&listener,
              LISTENER,
              mio::Ready::readable(),
              mio::PollOpt::level()).unwrap();
```
3. App initialise a new TlsServer in enclave by calling the following function:

```rust
 let mut tlsserv = TlsServer::new(enclave.geteid(), listener, ServerMode::Echo, cert, key);
```

4. Within the enclave, the TlsServer will be initiated with a new session created for the configuration. The handshake protocol is done through a [modified version](https://github.com/mesalock-linux/rustls) of the `rustls` library, which has been modified to be compatible with Intel SGX.

```rust
fn new(fd: c_int, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
    TlsServer {
        socket: TcpStream::new(fd).unwrap(),
        tls_session: rustls::ServerSession::new(&cfg)
    }
}
```



#### Accepting connection

1. Whenever there is a new connection, the `poll` engine will pick up the event and accept the connection
   
   ```rust

   // acceting an event
    'outer: loop {
        poll.poll(&mut events, None)
            .unwrap();

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    if !tlsserv.accept(&mut poll) {
                        break 'outer;
                    }
                }
                _ => tlsserv.conn_event(&mut poll, &event)
            }
        }
    }


    fn accept(&mut self, poll: &mut mio::Poll) -> bool {
        match self.server.accept() {
            Ok((socket, addr)) => {

                println!("Accepting new connection from {:?}", addr);

                let mut tlsserver_id: usize = 0xFFFF_FFFF_FFFF_FFFF;
                let retval = unsafe {
                    tls_server_new(self.enclave_id,
                                   &mut tlsserver_id,
                                   socket.as_raw_fd(),
                                   self.cert.as_bytes_with_nul().as_ptr() as * const c_char,
                                   self.key.as_bytes_with_nul().as_ptr() as * const c_char)
                };

                if retval != sgx_status_t::SGX_SUCCESS {
                    println!("[-] ECALL Enclave [tls_server_new] Failed {}!", retval);
                    return false;
                }

                if tlsserver_id == 0xFFFF_FFFF_FFFF_FFFF {
                    println!("[-] New enclave tlsserver error");
                    return false;
                }

                let mode = self.mode.clone();
                let token = mio::Token(self.next_id);
                self.next_id += 1;
                self.connections.insert(token, Connection::new(self.enclave_id,
                                                               socket,
                                                               token,
                                                               mode,
                                                               tlsserver_id));
                self.connections[&token].register(poll);
                true
            }
            Err(e) => {
                println!("encountered error while accepting connection; err={:?}", e);
                false
            }
        }
    }
   ```
2. The server will establish a connection with the client
3. If the client is sending data, the server will attempt to read the data from the app (`main.rs`)

```rust
fn read_tls(&self, buf: &mut [u8]) -> isize {
        let mut retval = -1;
        let result = unsafe {
            tls_server_read(self.enclave_id,
                            &mut retval,
                            self.tlsserver_id,
                            buf.as_ptr() as * mut c_void,
                            buf.len() as c_int)
        };
        match result {
            sgx_status_t::SGX_SUCCESS => { retval as isize },
            _ => {
                println!("[-] ECALL Enclave [tls_server_wants_read] Failed {}!", result);
                return -1;
            },
        }
    }
```

4. The TLS data will read the data sent within the enclave:
   
```rust
#[no_mangle]
pub extern "C" fn tls_server_read(session_id: size_t, buf: * mut c_char, cnt: c_int) -> c_int {
    if let Some(session_ptr) = Sessions::get_session(session_id) {
        let session = unsafe { &mut *(session_ptr) };
        if buf.is_null() || cnt == 0 {
            // just read_tls
            session.do_read()
        } else {
            if !rsgx_raw_is_outside_enclave(buf as * const u8, cnt as usize) {
                return -1;
            }
            // read plain buffer
            let mut plaintext = Vec::new();
            let mut result = session.read(&mut plaintext);

            // process the retrieval of DID and sk_d2 and store them
            store_data_from_datareg(&plaintext);

            if result == -1 {
                return result;
            }
            if cnt < result {
                result = cnt;
            }
            rsgx_sfence();
            let raw_buf = unsafe { slice::from_raw_parts_mut(buf as * mut u8, result as usize) };
            raw_buf.copy_from_slice(plaintext.as_slice());
            result
        }
    } else { -1 }
}
```

5. As the TLSServer is run by the authority, the authority should check for the TLSREquest and store the `DID` and `sk_d2` within the enclave. 








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
