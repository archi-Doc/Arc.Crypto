# Native AOT verification

## Result (2026-09-03)

Verified on Windows x64 with .NET SDK 10.0.400 / runtime 10.0.11:

- Native AOT publication and execution succeeded through a project reference.
- Native AOT publication and execution also succeeded using a locally packed NuGet package.
- Both publications analyzed the entire `Arc.Crypto` assembly and completed without trim/AOT warnings. Warnings are treated as errors.
- The publish directories contained the executable, `blake3_dotnet.dll`, and `libsodium.dll`. Execution from those directories succeeded.
- All 263 unit tests passed (244 before the changes, 19 additional regression cases).

Windows x64 is the platform executed locally. The CI workflow now includes Windows x64 and Linux x64, for both reference types. Linux, macOS, ARM64, and other RIDs have not been executed in this local verification; bundled native assets alone do not establish compatibility on those platforms.

## Reproduce

Install the [Native AOT prerequisites](https://learn.microsoft.com/dotnet/core/deploying/native-aot/) for the target platform, then run from the repository root:

```sh
dotnet test --project Test/Test.csproj -c Release
dotnet publish AotSmoke/AotSmoke.csproj -c Release -r win-x64 -o artifacts/aot
./artifacts/aot/AotSmoke.exe
```

For Linux x64, replace `win-x64` with `linux-x64` and run `./artifacts/aot/AotSmoke`.

The local Windows environment had an MSVC linker but no installed Windows SDK libraries. For this verification, the Microsoft `Microsoft.Windows.SDK.CPP.x64` 10.0.26100.7175 package was extracted under the ignored `artifacts/toolchain` directory, and its libraries and the existing MSVC tools were supplied through process-local `LIB`/`PATH` with `IlcUseEnvironmentalTools=true`. No system installation or permanent environment change was made. A normal C++/Windows SDK installation does not require that workaround.

To test the NuGet path, pack a unique local prerelease version, restore the consumer with `ArcCryptoPackageVersion` set to that version and the absolute local package directory as an additional source, then publish with the same property and `--no-restore`. The CI workflow contains the complete commands. Use a fresh package version when repeating after code changes to avoid reusing a cached package.

Deploy the complete publish directory. This library still uses shared native dependencies; Native AOT does not embed libsodium or BLAKE3 into the executable.

## Coverage

`AotSmoke` uses `TrimmerRootAssembly` to retain the whole library for analysis, following [Microsoft's library compatibility testing guidance](https://learn.microsoft.com/dotnet/core/deploying/trimming/prepare-libraries-for-trimming). It also checks that dynamic code is unavailable, so accidentally running the managed build cannot count as successful AOT validation.

Runtime checks include:

- BLAKE3 known vectors for empty and 1025-byte inputs, keyed hashing and key derivation; incremental, generic, parallel, reset, struct and extended output APIs. Keyed and derivation vectors come from the [official BLAKE3 test vectors](https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json).
- Libsodium random bytes, XSalsa20-Poly1305, X25519 key agreement, Ed25519, Ed25519ph and dual key conversion.
- Argon2id verification and failure reporting, password encryption and wrong-password rejection.
- AEGIS-256 and AEGIS-128L, authentication failure, BLAKE2b, SHA-2, SHA-3, incremental hashes, encodings, random generators and elliptic curve point decompression.

The original QuickStart-based CI check did not invoke BLAKE3 or root the entire library. The dedicated executable now fails when a checked result is incorrect and validates actual native loading through both project and package references.

## Changes

- Centralized BLAKE3 asset copying in the library project. Project consumers now receive the native library automatically, with the target RID preferred over the SDK host RID. Removed duplicate copy rules from the sample, test and benchmark projects. NuGet retains all existing RID-specific assets.
- Restored thread-safe, one-time libsodium initialization before its first use. This initializes the random source and CPU implementation selection. The [libsodium usage contract](https://github.com/jedisct1/libsodium-doc/blob/master/usage/README.md) requires initialization before other functions.
- Added the missing state check to `Blake3Hasher.Finalize()`, preventing null native pointer access after default construction or disposal.
- Ensured empty BLAKE3 spans do not pass null pointers to Rust slice construction. Empty updates and outputs skip native calls.
- Changed generic BLAKE3 byte-length multiplication to checked native-width arithmetic, avoiding 32-bit integer overflow on large typed spans.
- Kept normal GC transitions for potentially blocking native allocation/free and key-context processing, and for large extended hash outputs. Short hash/update/output calls retain the existing optimized path.
- Made both password hash generation overloads throw `CryptographicException` when the native operation fails. The native output parameter is now correctly declared writable.
- Guaranteed null termination for password hash verification, including rejecting a full 128-byte buffer without a terminator.
- Used bounded stack buffers for short UTF-8 passwords and hash buffers, and cleared temporary password bytes after use, including failure paths.

## Allocation measurement

Compared the original verification methods from Git HEAD with the modified methods on the same .NET 10 Windows x64 process. The benchmark used the valid password `password`, an Argon2id hash generated with one pass and 8192 bytes of memory for a fast verification workload, 1000 warm-up calls and 10000 measured calls. These reduced costs were used only for measurement; production defaults are unchanged.

| Verification overload | Before | After |
| --- | ---: | ---: |
| String hash and password | 184 managed bytes/call | 0 managed bytes/call |
| UTF-8 hash and password | 152 managed bytes/call | 0 managed bytes/call |

Measured with `GC.GetAllocatedBytesForCurrentThread`. This measures managed allocation, not native allocation or elapsed-time speedup. Passwords exceeding the 256-byte UTF-8 stack threshold still use a temporary managed array, which is cleared after use.
