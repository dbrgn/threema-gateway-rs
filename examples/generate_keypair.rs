use crypto_secretbox::aead::OsRng;
use data_encoding::HEXLOWER;

fn main() {
    println!("Generating new random nacl/libsodium crypto box keypair:\n");
    let sk = crypto_box::SecretKey::generate(&mut OsRng);
    let pk = sk.public_key();
    println!("   Public: {}", HEXLOWER.encode(pk.as_bytes()));
    println!("  Private: {}", HEXLOWER.encode(&sk.to_bytes()));
    println!("\nKeep the private key safe, and don't share it with anybody!");
}
