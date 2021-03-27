use data_encoding::HEXLOWER;
use sodiumoxide::crypto::box_;

fn main() {
    println!("Generating new random nacl/libsodium crypto box keypair:\n");
    let (pk, sk) = box_::gen_keypair();
    println!("   Public: {}", HEXLOWER.encode(&pk.0));
    println!("  Private: {}", HEXLOWER.encode(&sk.0));
    println!("\nKeep the private key safe, and don't share it with anybody!");
}
