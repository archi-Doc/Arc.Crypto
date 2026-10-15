#!/bin/sh
set -eu
# Links against glibc 2.17 (cargo-zigbuild + zig) so the library loads on older distributions (e.g. RHEL 8).
TARGET="x86_64-unknown-linux-gnu"
GLIBC="2.17"
BUILD="linux-x64"
rustup target add $TARGET
cargo zigbuild --release --target $TARGET.$GLIBC
mkdir -p build/$BUILD/native
cp target/$TARGET/release/libblake3_dotnet.so build/$BUILD/native
strip build/$BUILD/native/*.so
