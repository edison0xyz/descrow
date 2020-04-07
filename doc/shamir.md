# Shamir

To split the key into two `sk_d1` and `sk_d2`, we implement a shamir secret sharing algorithm that works within the enclave

## Creating the secret share

1. Instantiating the SecretData. We first instantiate a new Secret with `with_secret` function. The private key is passed in as a string, and the threshold is the number of keys it take to reconstruct the secret. 

```rust
pub fn with_secret(secret: &str, threshold: u8) -> SecretData {
    let mut coefficients: Vec<Vec<u8>> = vec![];
    println!("In SecretData");

    let rand_container = vec![0u8; (threshold - 1) as usize];

    for c in secret.as_bytes() {
        
        thread_rng().fill_bytes(&mut rand_container);
        let mut coef: Vec<u8> = vec![*c];
        for r in rand_container.iter() {
            coef.push(*r);
        }
        coefficients.push(coef);
    }
    println!("Secret successfully split into {:?} shares.", threshold);
    SecretData {
        secret_data: Some(secret.to_string()),
        coefficients,
    }
}
```

2. Retrieving the two shares, `sk_d1` and `sk_d2`: Once the secret is initiated, we could call the `get_share` method to obtain two shares.

```rust

  pub fn get_share(&self, id: u8) -> Result<Vec<u8>, ShamirError> {
        if id == 0 {
            return Err(ShamirError::InvalidShareCount);
        }
        let mut share_bytes: Vec<u8> = vec![];
        let coefficients = self.coefficients.clone();
        for coefficient in coefficients {
            let b = (SecretData::accumulate_share_bytes(id, coefficient))?;
            share_bytes.push(b);
        }

        share_bytes.insert(0, id);
        Ok(share_bytes)
    }

     fn accumulate_share_bytes(id: u8, coefficient_bytes: Vec<u8>) -> Result<u8, ShamirError> {
        if id == 0 {
            return Err(ShamirError::InvalidShareCount);
        }
        let mut accumulator: u8 = 0;

        let mut x_i: u8 = 1;

        for c in coefficient_bytes {
            accumulator = SecretData::gf256_add(accumulator, SecretData::gf256_mul(c, x_i));
            x_i = SecretData::gf256_mul(x_i, id);
        }

        Ok(accumulator)
    }
```

The enclave will then call the following functions in the main function.
```rust
    let secret_data = SecretData::with_secret(private_key, 2); // denotes two keys are required to reconstruct the secret
    let sk_d1 = secret_data.get_share(1).unwrap(); // getting first key 
    let sk_d2 = secret_data.get_share(2).unwrap(); // getting second key
```


## Reconstructing the shared secret

To reconstruct the one key from two shares, we will have to recover the secret

1. The secrets are parsed as a `vector` to the `recover_secret` method. The method will validate the shares and attempt the reconstructing of the share

```rust
pub fn recover_secret(threshold: u8, shares: Vec<Vec<u8>>) -> Option<String> {
        if threshold as usize > shares.len() {
            println!("Number of shares is below the threshold");
            return None;
        }
        let mut xs: Vec<u8> = vec![];

        for share in shares.iter() {
            if xs.contains(&share[0]) {
                println!("Multiple shares with the same first byte");
                return None;
            }

            if share.len() != shares[0].len() {
                println!("Shares have different lengths");
                return None;
            }

            xs.push(share[0].to_owned());
        }
        let mut mycoefficients: Vec<String> = vec![];
        let mut mysecretdata: Vec<u8> = vec![];
        let rounds = shares[0].len() - 1;

        for byte_to_use in 0..rounds {
            let mut fxs: Vec<u8> = vec![];
            for share in shares.clone() {
                fxs.push(share[1..][byte_to_use]);
            }

            match SecretData::full_lagrange(&xs, &fxs) {
                None => return None,
                Some(resulting_poly) => {
                    mycoefficients.push(String::from_utf8_lossy(&resulting_poly[..]).to_string());
                    mysecretdata.push(resulting_poly[0]);
                }
            }
        }

        match String::from_utf8(mysecretdata) {
            Ok(s) => Some(s),
            Err(e) => {
                println!("{:?}", e);
                None
            }
        }
    }

```

2. Within the reconstructing phase, there is a method called `full_lagrange` which constructs the Lagrange basis polynomial. The specifics of the mathematics behind Shamir Secret Sharing is made available [here](https://ericrafaloff.com/shamirs-secret-sharing-scheme/).

```rust
fn full_lagrange(xs: &[u8], fxs: &[u8]) -> Option<Vec<u8>> {
        let mut returned_coefficients: Vec<u8> = vec![];
        let len = fxs.len();
        for i in 0..len {
            let mut this_polynomial: Vec<u8> = vec![1];

            for j in 0..len {
                if i == j {
                    continue;
                }

                let denominator = SecretData::gf256_sub(xs[i], xs[j]);
                let first_term = SecretData::gf256_checked_div(xs[j], denominator);
                let second_term = SecretData::gf256_checked_div(1, denominator);
                match (first_term, second_term) {
                    (Some(a), Some(b)) => {
                        let this_term = vec![a, b];
                        this_polynomial =
                            SecretData::multiply_polynomials(&this_polynomial, &this_term);
                    }
                    (_, _) => return None,
                };
            }
            if fxs.len() + 1 >= i {
                this_polynomial = SecretData::multiply_polynomials(&this_polynomial, &[fxs[i]])
            }
            returned_coefficients =
                SecretData::add_polynomials(&returned_coefficients, &this_polynomial);
        }
        Some(returned_coefficients)
    }
```