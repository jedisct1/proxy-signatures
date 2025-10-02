//! Command-line interface for proxy signatures
//!
//! Run the example with: `cargo run --example demo`

use libsodium_rs::ensure_init;

fn main() {
    if let Err(e) = ensure_init() {
        eprintln!("Failed to initialize libsodium: {}", e);
        std::process::exit(1);
    }

    println!("Proxy Signatures Library");
    println!("========================");
    println!();
    println!("This is a library for Ristretto255 proxy signatures.");
    println!();
    println!("To see a demonstration, run:");
    println!("  cargo run --example demo");
    println!();
    println!("To run tests:");
    println!("  cargo test");
}
