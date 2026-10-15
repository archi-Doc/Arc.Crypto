#!/bin/sh
set -eu
# Links against glibc 2.17 (cargo-zigbuild + zig) so the library loads on older distributions.
TARGET="arm-unknown-linux-gnueabihf"
GLIBC="2.17"
BUILD="linux-arm"
rustup target add $TARGET
cargo zigbuild --release --target $TARGET.$GLIBC
mkdir -p build/$BUILD/native
cp target/$TARGET/release/libblake3_dotnet.so build/$BUILD/native
arm-linux-gnueabihf-strip build/$BUILD/native/*.so
