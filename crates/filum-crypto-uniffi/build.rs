fn main() {
    println!("cargo:rerun-if-changed=src/filum_crypto.udl");
    println!("cargo:rerun-if-changed=uniffi.toml");
    println!("cargo:rerun-if-changed=build.rs");
    uniffi::generate_scaffolding("src/filum_crypto.udl").unwrap();
}
