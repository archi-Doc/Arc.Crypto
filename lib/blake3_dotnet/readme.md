# blake3_dotnet

BLAKE3 Rust libraries compiled to native and exposed as plain shared libraries.

## How to build?

You need to have [`rustup`](https://rustup.rs/) installed

Run one of the `build*` scripts (e.g `build-win-x64.ps1` or `build-linux-x64.sh`).

Musl targets are supported via:
- `build-linux-musl-x64.sh` (`x86_64-unknown-linux-musl`)
- `build-linux-musl-arm64.sh` (`aarch64-unknown-linux-musl`)

The binaries in `Arc.Crypto/runtimes` must be rebuilt for every RID after changing this source; the bundled binaries predate zeroing the hasher on delete and the static CRT for win-arm64, and the bundled Linux glibc binaries require GLIBC_2.34.

`build-win-arm.ps1` (32-bit ARM, `thumbv7a-uwp-windows-msvc`) writes to `build/win-arm`. Its output is not shipped, and its target is Rust tier 3 (no prebuilt standard library).

### Linux (glibc)

`build-linux-x64.sh`, `build-linux-arm64.sh` and `build-linux-arm.sh` link against glibc 2.17 with [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild), so the libraries also load on older distributions such as RHEL 8 (a plain `cargo build` links against the build machine's glibc). They need `cargo-zigbuild` and zig, plus binutils for the target (`strip`, `aarch64-linux-gnu-strip`, `arm-linux-gnueabihf-strip`):

```sh
python3 -m venv ~/zigbuild
~/zigbuild/bin/pip install cargo-zigbuild==0.23.4 ziglang==0.16.0
export PATH="$HOME/zigbuild/bin:$PATH"
sudo apt-get install -y binutils-aarch64-linux-gnu binutils-arm-linux-gnueabihf
```

`check-glibc.sh <max-glibc-version> <objdump> <library>...` fails if `objdump -T` shows a newer `GLIBC_` symbol version, e.g. `./check-glibc.sh 2.17 aarch64-linux-gnu-objdump build/linux-arm64/native/libblake3_dotnet.so`.

### Windows

ml64 (MASM) rejects long object paths (`A1009: line too long`), so keep the cargo target directory short, e.g. `$env:CARGO_TARGET_DIR="C:\b3t"` when the repository is deeply nested.

## Rebuilding the shipped binaries

The `native` workflow (`.github/workflows/native.yml`, manual trigger) builds every shipped RID with a pinned Rust toolchain and fails if a Linux glibc library needs a glibc newer than 2.17.

| Artifact | RIDs |
| --- | --- |
| `native-ubuntu-latest` | `linux-x64`, `linux-arm64`, `linux-arm` |
| `native-macos-latest` | `osx-x64`, `osx-arm64`, `linux-musl-x64`, `linux-musl-arm64` |
| `native-windows-latest` | `win-x64`, `win-x86`, `win-arm64` |

Run these from the repository root.

1. Push the branch, then run the workflow on it and wait for all three jobs to pass:
   ```sh
   gh workflow run native.yml --ref dev
   gh run list --workflow native.yml --branch dev --limit 1
   gh run watch <run-id> --exit-status
   ```
2. Download the artifacts and copy them over the shipped binaries (each artifact holds `<rid>/native/<library>`):
   ```sh
   gh run download <run-id> --dir native-artifacts
   for a in native-artifacts/native-*; do cp -r "$a"/. Arc.Crypto/runtimes/; done
   rm -rf native-artifacts
   ```
3. `git status Arc.Crypto/runtimes` should show exactly ten modified libraries and nothing new.
4. Run `dotnet test --project Test/Test.csproj -c Release` (on Linux too if possible), then commit the libraries together with the source change.
