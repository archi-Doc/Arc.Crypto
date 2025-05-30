#!/bin/sh
TARGET="x86_64-apple-darwin"
BUILD="osx-x64"
rustup target add $TARGET
cargo build --release --target $TARGET
mkdir -p build/$BUILD/native
cp target/$TARGET/release/libblake3_dotnet.dylib build/$BUILD/native/blake3_dotnet.so