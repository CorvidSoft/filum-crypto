fn main() {
    println!("cargo:rerun-if-changed=src/filer_crypto.udl");
    println!("cargo:rerun-if-changed=uniffi.toml");
    println!("cargo:rerun-if-changed=build.rs");
    uniffi::generate_scaffolding("src/filer_crypto.udl").unwrap();
}
