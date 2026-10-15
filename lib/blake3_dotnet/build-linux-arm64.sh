#!/bin/sh
set -eu
# Links against glibc 2.17 (cargo-zigbuild + zig) so the library loads on older distributions (e.g. RHEL 8).
TARGET="aarch64-unknown-linux-gnu"
GLIBC="2.17"
BUILD="linux-arm64"
rustup target add $TARGET
cargo zigbuild --release --target $TARGET.$GLIBC
mkdir -p build/$BUILD/native
cp target/$TARGET/release/libblake3_dotnet.so build/$BUILD/native
aarch64-linux-gnu-strip build/$BUILD/native/*.so
