fn main() {
    // The target triple this crate is compiled for, i.e. the host the final
    // binary runs on.
    let target = std::env::var("TARGET").expect("TARGET is set by Cargo");
    println!("cargo:rustc-env=CARGO_LIVE_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
