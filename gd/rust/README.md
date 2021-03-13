Rust build
======

Currently, the Rust components are built differently on Android vs Linux. We are
missing Rust support in our GN toolchain so we currently build the Rust
libraries as a staticlib and link in C++. This may change in the future once we
have better support.

For now, you can build all of the Rust code using Cargo.

There are some dependencies:
* You must have the protobuf-compiler package installed
* You must have a recent version of Cargo + Rust

You should use `build.py` at the root to do your Rust builds so that it
correctly points your dependencies towards the vendored crates and sets your
$CARGO_HOME to the correct location.
