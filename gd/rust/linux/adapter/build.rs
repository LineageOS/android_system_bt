use pkg_config::Config;

fn main() {
    // The main linking point with c++ code is the libbluetooth-static.a
    // These includes all the symbols built via C++ but doesn't include other
    // links (i.e. pkg-config)
    println!("cargo:rustc-link-lib=static=bluetooth-static");

    // A few dynamic links
    println!("cargo:rustc-link-lib=dylib=flatbuffers");
    println!("cargo:rustc-link-lib=dylib=protobuf");
    println!("cargo:rustc-link-lib=dylib=resolv");

    // Clang requires -lc++ instead of -lstdc++
    println!("cargo:rustc-link-lib=c++");

    // A few more dependencies from pkg-config. These aren't included as part of
    // the libbluetooth-static.a
    Config::new().probe("libchrome").unwrap();
    Config::new().probe("libmodp_b64").unwrap();
    Config::new().probe("tinyxml2").unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=libbluetooth-static.a");
}
