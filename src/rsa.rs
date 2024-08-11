use num_bigint::{BigUint, ToBigUint};
use num_primes::{Generator, Verification};
use num_traits::{One, ToPrimitive};
use crate::utils::mod_inv;

#[derive(Debug)]
pub struct RSA {
    n: num_primes::BigUint,
    e: BigUint,
    d: BigUint,
}

impl RSA {
    pub fn new() -> Self {
        let p = Generator::new_prime(1024);
        let p_c = BigUint::from_bytes_be(&p.clone().to_bytes_be());
        let q = Generator::new_prime(1024);
        let q_c = BigUint::from_bytes_be(&q.clone().to_bytes_be());

        let is_prime = Verification::is_prime(&p);
        assert_eq!(is_prime, true);
        // assert_eq!(is_safe_prime, true);
        let is_prime = Verification::is_prime(&q);
        assert_eq!(is_prime, true);
        // assert_eq!(is_safe_prime, true);

        let n = p*q;
        let phi = (p_c - BigUint::one())*(q_c - BigUint::one());
        
        let e = 0x10001.to_biguint().unwrap();
        let d = mod_inv(&e, phi).expect("Failed to calculate private key!");

        Self { n, e, d }
    }

    pub fn encrypt(&self, msg: &String) -> Vec<BigUint> {
        let msg_bytes = msg.as_bytes();
        msg_bytes
            .iter()
            .map(|&byte| {
                let byte_biguint = byte.to_biguint().unwrap();
                let n_c = BigUint::from_bytes_be(&self.n.clone().to_bytes_be());
                byte_biguint.modpow(&self.e, &n_c)
            })
            .collect()
    }

    pub fn decrypt(&self, ciphertext: &Vec<BigUint>) -> String {
        let n_c = BigUint::from_bytes_be(&self.n.clone().to_bytes_be());
        let decrypted_bytes: Vec<u8> = ciphertext
            .iter()
            .map(|c| c.modpow(&self.d, &n_c).to_u8().unwrap())
            .collect();
        String::from_utf8(decrypted_bytes).expect("Decryption failed")
    }
}