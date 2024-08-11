pub mod rsa;
pub mod utils;

fn main() {
    let msg = "Hello, world!".to_string();
    let rsa = rsa::RSA::new();

    let ciphertext = rsa.encrypt(&msg);
    print!("Encrypted: {:#?}\n\n", ciphertext);
    let plaintext = rsa.decrypt(&ciphertext);
    print!("Decrypted: {}", plaintext);
    assert!(plaintext == msg);
}
