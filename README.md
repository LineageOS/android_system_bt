# Fluoride Bluetooth stack

## Building and running on AOSP
Just build AOSP - Fluoride is there by default.

## Building and running on Linux

Instructions for a Debian based distribution:
* Debian Bullseye or newer
* Ubuntu 20.10 or newer
* Clang-11 or Clang-12
* Flex 2.6.x
* Bison 3.x.x (tested with 3.0.x, 3.2.x and 3.7.x)

You'll want to download some pre-requisite packages as well. If you're currently
configured for AOSP development, you should have all required packages.
Otherwise, you can use the following apt-get list:

```sh
sudo apt-get install repo git-core gnupg flex bison gperf build-essential \
  zip curl zlib1g-dev gcc-multilib g++-multilib \
  x11proto-core-dev libx11-dev lib32z-dev libncurses5 \
  libgl1-mesa-dev libxml2-utils xsltproc unzip liblz4-tool libssl-dev \
  libc++-dev libevent-dev \
  flatbuffers-compiler libflatbuffers1 \
  openssl openssl-dev
```

You will also need a recent-ish version of Rust and Cargo. Please follow the
instructions on [Rustup](https://rustup.rs/) to install a recent version.

### Download source

```sh
mkdir ~/fluoride
cd ~/fluoride
git clone https://android.googlesource.com/platform/system/bt
```

Install dependencies (require sudo access). This adds some Ubuntu dependencies
and also installs GN (which is the build tool we're using).

```sh
cd ~/fluoride/bt
build/install_deps.sh
```

The following third-party dependencies are necessary but currently unavailable
via a package manager. You may have to build these from source and install them
to your local environment.

TODO(abhishekpandit) - Provide a pre-packaged option for these or proper build
instructions from source.

* libchrome
* modp_b64
* tinyxml2

### Stage your build environment

For host build, we depend on a few other repositories:
* [Platform2](https://chromium.googlesource.com/chromiumos/platform2/)
* [Rust crates](https://chromium.googlesource.com/chromiumos/third_party/rust_crates/)
* [Proto logging](https://android.googlesource.com/platform/frameworks/proto_logging/)

Clone these all somewhere and create your staging environment.
```sh
export STAGING_DIR=path/to/your/staging/dir
mkdir ${STAGING_DIR}
mkdir -p ${STAGING_DIR}/external
ln -s $(readlink -f ${PLATFORM2_DIR}/common-mk) ${STAGING_DIR}/common-mk
ln -s $(readlink -f ${PLATFORM2_DIR}/.gn) ${STAGING_DIR}/.gn
ln -s $(readlink -f ${RUST_CRATE_DIR}) ${STAGING_DIR}/external/rust
ln -s $(readlink -f ${PROTO_LOG_DIR}) ${STAGING_DIR}/external/proto_logging
```

### Build

We provide a build script to automate building assuming you've staged your build
environment already as above.


```sh
./build.py --output ${OUTPUT_DIR} --platform-dir ${STAGING_DIR} --clang
```

This will build all targets to the output directory you've given. You can also
build each stage separately (if you want to iterate on something specific):

* prepare - Generate the GN rules
* tools - Generate host tools
* rust - Build the rust portion of the build
* main - Build all the C/C++ code
* test - Build all targets and run the tests
* clean - Clean the output directory

You can choose to run only a specific stage by passing an arg via `--target`.

Currently, Rust builds are a separate stage that uses Cargo to build. See
[gd/rust/README.md](gd/rust/README.md) for more information.

### Run

By default on Linux, we statically link libbluetooth so you can just run the
binary directly:

```sh
cd ~/fluoride/bt/out/Default
./bluetoothtbd -create-ipc-socket=fluoride
```
