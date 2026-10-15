# Arc.Crypto

Arc.Crypto is a .NET 10 library of cryptographic primitives, fast hashes, random number generators, and encoders. It focuses on span-based, allocation-free APIs and uses hardware acceleration where available.

| Area | Implementations |
| --- | --- |
| Authenticated encryption | AEGIS-256, AEGIS-128L, XSalsa20-Poly1305 (`CryptoSecretBox`) |
| Passwords | `PasswordEncryption` (Argon2id + AEGIS-256), Argon2id key derivation and password hashes (`CryptoPasswordHash`) |
| Public keys | Ed25519 (`CryptoSign`), Ed25519ph, X25519 + XSalsa20-Poly1305 (`CryptoBox`), shared signing/encryption keys (`CryptoDual`) |
| Elliptic-curve helpers | secp256k1 and secp256r1 field arithmetic, point compression, seed validation |
| Cryptographic hashes | BLAKE3 (one-shot, incremental, keyed, key derivation, XOF), BLAKE2b, SHA-2, SHA-3; legacy SHA-1 |
| Non-cryptographic hashes | xxHash3, xxHash64, xxHash32, FarmHash64, CRC-32, Adler-32 |
| Random numbers | xoshiro256\*\*, xoroshiro128\*\*, Xorshift, MT19937-64, `AegisRandom`, `CryptoRandom`, `RandomVault` |
| Encoding and comparison | Hex, Base64 (`FastBase64`), Base64Url (`FastBase64Url`), sortable Base32 (`Base32Sort`), UTF-8/UTF-16 array comparers |

## Contents

- [Installation](#installation)
- [Platforms and native libraries](#platforms-and-native-libraries)
- [Authenticated encryption](#authenticated-encryption)
- [Passwords](#passwords)
- [Public keys](#public-keys)
- [Elliptic-curve helpers](#elliptic-curve-helpers)
- [Hashing](#hashing)
- [Random numbers](#random-numbers)
- [Encoding and comparison](#encoding-and-comparison)
- [Thread safety](#thread-safety)
- [Building and testing](#building-and-testing)
- [Migration and license](#migration-and-license)

## Installation

```sh
dotnet add package Arc.Crypto
```

```csharp
using Arc.Crypto;
```

The package targets .NET 10 and depends on `Arc.Collections` and `libsodium`.

## Platforms and native libraries

| Native library | Used by | Source |
| --- | --- | --- |
| libsodium | `CryptoSecretBox`, `CryptoBox`, `CryptoSign`, `CryptoDual`, `Ed25519ph`, `CryptoPasswordHash`, `PasswordEncryption`, `CryptoRandom`, `Blake2B` | `libsodium` NuGet package |
| blake3_dotnet | `Blake3`, `Blake3Hasher` | Bundled for win-x64, win-x86, win-arm64, linux-x64, linux-arm64, linux-arm, linux-musl-x64, linux-musl-arm64, osx-x64, osx-arm64 (built from `lib/blake3_dotnet`) |

AEGIS, SHA-3, the non-cryptographic hashes, the encoders, and the seeded pseudo-random generators are fully managed and need no native library.

NuGet consumers get the native library that matches their runtime identifier (RID). A project reference copies the BLAKE3 library for every bundled RID to `runtimes/<rid>/native/` in the output, including RID-specific builds and publishes (about 4 MB in total). At run time, Arc.Crypto loads the copy that matches the process. A distribution-specific RID such as `ubuntu.24.04-x64` falls back to the portable RID. Deploy the complete output directory, including its shared libraries.

Hardware acceleration is selected at run time:

| Feature | Accelerated paths | Fallback |
| --- | --- | --- |
| AEGIS-256 / AEGIS-128L, `AegisRandom` | x86 AES-NI, ARMv8 AES | Table-based software AES |
| CRC-32 | x86 PCLMULQDQ, ARM64 PMULL and CRC32 instructions | Slicing-by-8 tables |
| Adler-32 | AVX2, SSSE3 | Scalar |
| xxHash3 | AVX2, Vector128 (SSE2, AdvSimd) | Scalar |
| `FastBase64`, `FastBase64Url` | Encode and decode: AVX2, SSSE3 + SSE4.1. Encode only: BCL vectorized encoder on other Vector128 hardware such as ARM64 | Scalar |

The software AES fallback is not constant-time and may leak key material through cache-timing side channels. It is used only without hardware AES, for example on WASM, RISC-V, ARM cores without crypto extensions, or with `DOTNET_EnableAES=0` (x86/x64) or `DOTNET_EnableArm64Aes=0` (ARM64).

Native AOT and trimming analysis are enabled (`IsAotCompatible`). CI publishes the `AotSmoke` project as Native AOT on win-x64 and linux-x64, through both a project reference and the NuGet package. The test suite runs on linux-x64 and linux-arm64.

## Authenticated encryption

### AEGIS

```csharp
ReadOnlySpan<byte> message = "Message"u8;
Span<byte> key = stackalloc byte[Aegis256.KeySize];
Span<byte> nonce = stackalloc byte[Aegis256.NonceSize];
RandomVault.Default.NextBytes(key);
RandomVault.Default.NextBytes(nonce);

var cipher = new byte[message.Length + Aegis256.MinTagSize];
Aegis256.Encrypt(cipher, message, nonce, key, associatedData: "header"u8);

var plaintext = new byte[message.Length];
bool valid = Aegis256.TryDecrypt(plaintext, cipher, nonce, key, associatedData: "header"u8);
```

- AEGIS-256 uses a 32-byte key and nonce; AEGIS-128L uses 16 bytes each. Keys and nonces must have exactly these sizes.
- The ciphertext is the encrypted message followed by the tag. The tag is 16 bytes by default (`MinTagSize`) or 32 bytes (`MaxTagSize`). A tag size of 0 disables authentication and tamper detection.
- `TryDecrypt` returns `false` and clears the plaintext buffer when authentication fails. Invalid sizes throw `ArgumentOutOfRangeException`.
- In-place operation works when both spans start at the same address. An overlapping output may also start before the input; an output that starts after the input throws `ArgumentException`.
- Never reuse a nonce with the same key. Store or transmit the nonce with the ciphertext, and pass the same associated data when decrypting.

### XSalsa20-Poly1305

```csharp
ReadOnlySpan<byte> message = "Message"u8;
Span<byte> key = stackalloc byte[CryptoSecretBox.KeySize];
Span<byte> nonce = stackalloc byte[CryptoSecretBox.NonceSize];
CryptoSecretBox.CreateKey(key);
CryptoRandom.NextBytes(nonce);

var cipher = new byte[message.Length + CryptoSecretBox.MacSize];
CryptoSecretBox.Encrypt(message, nonce, key, cipher);

var plaintext = new byte[message.Length];
bool valid = CryptoSecretBox.TryDecrypt(cipher, nonce, key, plaintext);
```

`CryptoSecretBox` uses a 32-byte key, a 24-byte nonce, and a 16-byte MAC. Its output is the MAC followed by the encrypted message. Always check the result of `TryDecrypt` before using the output.

## Passwords

```csharp
PasswordEncryption.Encrypt("Message"u8, "correct", out var encrypted);
bool valid = PasswordEncryption.TryDecrypt(encrypted, "correct", out var decrypted);
bool invalid = PasswordEncryption.TryDecrypt(encrypted, "incorrect", out _); // false

string storedHash = CryptoPasswordHash.GetHashString("password");
bool matches = CryptoPasswordHash.VerifyHashString(storedHash, "password");
```

`PasswordEncryption` output is `[salt/nonce: 32 bytes][ciphertext][tag: 16 bytes]`, 48 bytes longer than the plaintext. A non-empty password is stretched with Argon2id (interactive cost: 2 passes, 64 MiB) and the data is encrypted with AEGIS-256. The format has no version or cost fields.

- An empty password skips Argon2id and uses the public salt as the key, so it provides no confidentiality or forgery protection. It is kept for compatibility; use a non-empty password for protected data.
- Span overloads need an exactly sized destination. Array overloads allocate the result. String passwords are encoded as UTF-8 (unpaired surrogates become U+FFFD); UTF-8 overloads skip the conversion. Temporary password bytes and derived keys are cleared after use.
- Buffers may overlap: the UTF-8 password of `Encrypt` may lie inside the output buffer, and the plaintext buffer of `TryDecrypt` may start at or before offset 32 of the ciphertext.

`CryptoPasswordHash.DeriveKey` derives a key of at least 16 bytes from a password and a 16-byte salt with Argon2id; `OperationLimit` and `MemoryLimit` select the cost. The key buffer may overlap the salt or password. Password hash strings (`GetHashString`, `GetUtf8HashString`) contain their own salt and cost parameters, so the optional cost arguments of `VerifyHashString` are ignored and kept only for compatibility. Argon2 memory is native and not visible in managed allocation measurements.

## Public keys

### Ed25519 and Ed25519ph

```csharp
Span<byte> secretKey = stackalloc byte[CryptoSign.SecretKeySize];
Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeySize];
Span<byte> signature = stackalloc byte[CryptoSign.SignatureSize];
CryptoSign.CreateKeyPair(secretKey, publicKey);
CryptoSign.Sign("Message"u8, secretKey, signature);
bool valid = CryptoSign.Verify("Message"u8, publicKey, signature);

var ph = Ed25519ph.New();
ph.Update("Mes"u8);
ph.Update("sage"u8);
ph.FinalizeAndSign(secretKey, signature);
```

Ed25519 uses a 32-byte seed, a 64-byte secret key (seed followed by the public key), a 32-byte public key, and a 64-byte signature. `CryptoSign` also converts a secret key to its seed or public key.

`Ed25519ph` (RFC 8032 pre-hashed Ed25519) signs a message supplied in fragments. Its signatures differ from plain Ed25519 signatures. The state resets after `FinalizeAndSign` or `FinalizeAndVerify`; `default(Ed25519ph)` behaves like `Ed25519ph.New()`.

### X25519 and `CryptoBox`

`CryptoBox` combines X25519 key agreement with XSalsa20-Poly1305. Encrypt with the sender's secret key and the recipient's public key; decrypt with the recipient's secret key and the sender's public key. Keys and seeds are 32 bytes, nonces 24 bytes, and the MAC 16 bytes; the output is the MAC followed by the encrypted message. `Encrypt` and `DeriveSharedSecret` throw `CryptographicException` for public keys rejected by libsodium; `TryDecrypt` returns `false`.

`CryptoBox.DeriveSharedSecret` returns the raw X25519 shared secret. Before using it as a session key, apply a KDF that binds both public keys in a fixed order and the protocol context. See [libsodium's key agreement guidance](https://doc.libsodium.org/advanced/scalar_multiplication).

### `CryptoDual`

`CryptoDual` derives an Ed25519 signing key pair and an X25519 encryption key pair from one seed, and converts between them. Its encryption public key stores an extra sign bit in the top bit, so it is not the standard X25519 key format. `BoxPublicKeyEquals` compares two such keys while ignoring that bit. Conversion does not validate a public key.

## Elliptic-curve helpers

The `Arc.Crypto.EC` namespace exposes `Secp256k1Curve.Instance` and `Secp256r1Curve.Instance`. They provide field arithmetic (`Element*` methods), point compression (`CompressY`, `DecompressY`), and seed validation (`IsValidSeed`); they do not implement ECDSA.

- Field elements are spans of eight 32-bit words, least significant word first, holding a value below the field prime. Results for non-canonical inputs are unspecified, so range-check untrusted values first. Byte encodings (coordinates, seeds, curve parameters) are big-endian.
- `DecompressY` returns `null` for coordinates outside the field or not on the curve.
- `IsValidSeed` checks the size, the range, and a NAF-weight heuristic. It is stricter than mathematical private-key validity and does not measure entropy.
- Treat the exposed curve parameter arrays as read-only.

## Hashing

```csharp
ReadOnlySpan<byte> data = "Message"u8;
ulong xxHash3 = XxHash3.Hash64(data);
ulong xxHash64 = XxHash64.Hash64(data);
ulong farmHash = FarmHash.Hash64(data);
uint crc32 = Crc32.Hash32(data);
uint adler32 = Adler32.Hash32(data);

Span<byte> digest = stackalloc byte[32];
Blake3.Get256Span(data, digest);
Blake2B.Get256Span(data, digest);
Sha2Helper.Get256Span(data, digest);
Sha3Helper.Get256Span(data, digest);

using var hasher = Blake3Hasher.New();
hasher.Update(data);
hasher.FinalizeHash(digest);
```

### Cryptographic hashes

- Static span methods do not allocate. BLAKE2b and BLAKE3 span methods require an output of exactly the hash size; SHA-2 and SHA-3 accept a larger buffer and leave the trailing bytes unchanged. Array methods allocate the result. Tuple methods (`Get256UInt64`, ...) return the digest as 64-bit words in native byte order; serialize the digest bytes for portable storage.
- `Sha2Helper` and the SHA-1/SHA-2 wrappers reuse pooled hash instances, which can allocate when the pool is empty.
- `Blake3Hasher` supports incremental hashing, keyed hashing (`NewKeyed`, 32-byte key), key derivation (`NewDeriveKey`), reset, multi-threaded updates (`UpdateParallel`), and output of any length. A derivation context identifies the application and must be valid UTF-8 (otherwise `ArgumentException`); append the key material with `Update`. Finalizing does not reset the state and can be repeated. The hasher owns native memory: dispose it, do not copy an initialized instance, and do not share it between threads.

### Non-cryptographic hashes

- `XxHash3` and `XxHash64`/`XxHash32` produce the same numeric values as `System.IO.Hashing`. `XxHash3` also has a seeded, incremental API (`new XxHash3(seed)`, `Append`, `GetCurrentHashAsUInt64`, `Reset`).
- `FarmHash.Hash64` computes Google's farmhashxo::Hash64. The `FarmHash` ref struct hashes incrementally (`Append`, `FinalizeHash`, `Reset`) without allocation; `FinalizeHash` does not change the state.
- `Crc32` is the IEEE CRC-32 used by zlib, identical to `System.IO.Hashing.Crc32`. `Adler32` follows RFC 1950.
- Overloads that take a `string` or `ReadOnlySpan<char>` hash the raw UTF-16 bytes, not UTF-8.
- These hashes and checksums do not resist deliberate collisions; never use them for authentication.

### `IHash`

`IHash` offers `GetHash` and incremental `HashInitialize`, `HashUpdate`, and `HashFinal` for `XxHash32`, `XxHash64`, `Adler32`, `Crc32`, `Sha1`, `Sha2_256`/`Sha2_384`/`Sha2_512`, and `Sha3_256`/`Sha3_384`/`Sha3_512`.

- Call `HashInitialize` before each new incremental calculation; whether `HashFinal` resets the state depends on the implementation (`Crc32` and the SHA classes reset, `Adler32` and the xxHash classes do not).
- `HashFinal` returns a new array; the SHA-3 classes can also write to a span. The checksums and xxHash classes return their value in native byte order (little-endian on common platforms), which for `XxHash32`/`XxHash64` is the reverse of the big-endian bytes of `System.IO.Hashing`.
- A one-shot `GetHash` call does not disturb an incremental calculation in progress. Dispose the SHA-1/SHA-2 wrappers.

## Random numbers

```csharp
var random = new Xoshiro256StarStar(42);
ulong value = random.NextUInt64();
int index = random.NextInt32(0, 100); // [0, 100)
double fraction = random.NextDouble(); // [0, 1)
var bytes = new byte[16];
random.NextBytes(bytes);

RandomVault.Default.NextBytes(bytes); // Cryptographically secure.
ulong secureValue = RandomVault.Default.NextUInt64();
ulong fastValue = RandomVault.Xoshiro.NextUInt64(); // Fast, not secure.
```

### Pseudo-random generators

xoshiro256\*\*, xoroshiro128\*\*, Xorshift, and MT19937-64 (`MersenneTwister`) derive from `RandomUInt64Base`. They are deterministic for a given seed, not cryptographically secure, and not thread-safe.

- `NextInt32()` and `NextInt64()` can return negative values; `NextInt31()` and `NextInt63()` return non-negative values.
- Bounded methods use an exclusive upper bound without modulo bias, reject inverted ranges, and return the lower bound when both bounds are equal. Single-bound overloads require a non-negative bound.
- `NextDouble()` returns [0, 1); `NextDoubleInclusive()` and `NextDoubleExclusive()` return [0, 1] and (0, 1).
- `MersenneTwister` seeds follow the reference `init_genrand64` and `init_by_array64` functions. Byte-array seeds must be non-empty and a multiple of 8 bytes (native byte order).

### Secure generators

- `CryptoRandom.NextBytes` calls libsodium's `randombytes_buf`.
- `AegisRandom` outputs an AEGIS-256 keystream, rekeyed every 1024 bytes from the operating-system RNG. It exposes only `NextBytes` and is not thread-safe.

### `RandomVault`

`RandomVault` makes a generator thread-safe by serializing calls with a lock and buffering its output in a 4 KiB buffer.

- `Default` (an alias of `Aegis`), `SystemRng` (`RandomNumberGenerator`), and `Libsodium` are cryptographically secure; `Xoshiro` is fast but not secure. Each shared vault is created on first use.
- A custom vault takes an `Action<Span<byte>>` and an optional threshold: after the buffered bytes are used, a remaining request larger than the threshold is filled directly by the generator.
- Do not use a wrapped mutable generator outside its vault.
- The buffer keeps generated bytes until it is refilled. For long-lived secrets that must not leave a heap copy, fill your own buffer with `RandomNumberGenerator.Fill` or `CryptoRandom.NextBytes`.

## Encoding and comparison

```csharp
byte[] data = [0, 1, 2, 3];
string hex = Hex.FromBytesToString(data); // "00010203"
string base64 = FastBase64.EncodeToString(data); // "AAECAw=="
string url = FastBase64Url.EncodeToString(data); // "AAECAw"
string base32 = Base32Sort.Default.FromBytesToString(data); // "000H40S"
```

### Base64

`FastBase64` (RFC 4648 Base64) and `FastBase64Url` (URL-safe alphabet, no padding on output) encode into caller-supplied UTF-8 or UTF-16 spans, or into a string.

- Decoding accepts padded or unpadded input and is strict: it rejects whitespace, characters outside the alphabet, and non-zero unused bits in the final character (for example `AB==`, which `Convert.FromBase64String` accepts).
- `TryDecode` returns `false` on invalid input and sets `bytesWritten` to 0; the destination may then be partially written, but bytes past the decoded length are never modified. `Decode` throws `FormatException` instead.
- `GetEncodedLength` and `GetMaxDecodedLength` size buffers. `GetDecodedLength` inspects only the length and the trailing padding, not the alphabet.

### Base32Sort

`Base32Sort` uses the alphabet `0123456789ABCEFGHJKMNPQRSTUVWXYZ` without padding, so encoded strings sort in the same order as their bytes (ordinal comparison).

- `Default` is the table-driven converter (`Table`); `Reference` is a simpler implementation that produces the same results.
- Decoding accepts lower-case letters and maps `I`, `i`, `l` to `1` and `O`, `o` to `0`. It rejects `D`, `d`, and upper-case `L`.
- Decoding is lenient at the end: bits that do not complete a byte are ignored, including a whole trailing character when the length is 1, 3, or 6 modulo 8 (the character must still be valid).
- Span decoders return `false` and set `written` to 0 on invalid input; the destination may be partially written. Array decoders return an empty array on invalid input, which is also the result for valid empty input, so prefer the span decoders when the difference matters.
- Length helpers and encoders throw `ArgumentOutOfRangeException` for negative lengths or an encoded length above `int.MaxValue`.

### Hex

`Hex.FromBytesToString` writes lower-case digits. `Hex.FromStringToByteArray` accepts both cases and throws `ArgumentException` for an odd length and `FormatException` for an invalid digit.

### Array comparers

`Utf8StringEqualityComparer` (`byte[]`) and `Utf16StringEqualityComparer` (`char[]`) compare arrays by ordinal content, without case folding or Unicode normalization. They support allocation-free `ReadOnlySpan<T>` lookups in `Dictionary` through alternate comparers; adding a key from a span copies it into a new array. Hash codes are XXH3 values with a random per-process seed, so they differ between processes and must not be persisted. Do not modify an array while it is a dictionary key.

## Thread safety

| Thread-safe | Not thread-safe (use one instance per thread) |
| --- | --- |
| All static methods, `RandomVault`, `CryptoRandom` | `IHash` instances, `Blake3Hasher`, `FarmHash`, `XxHash3` instances, `Ed25519ph`, `AegisRandom`, `RandomUInt64Base` generators |

## Building and testing

```sh
dotnet build Arc.Crypto.slnx -c Release
dotnet test --project Test/Test.csproj -c Release --no-build
```

The tests use known-answer vectors (RFC 8032, the BLAKE3 test vectors, Google's FarmHash self-test, the AEGIS draft), cross-checks against the BCL, `System.IO.Hashing`, and libsodium, malformed and boundary inputs, overlapping buffers, authentication failures, and managed-allocation regressions. To exercise the portable code paths, repeat the test run with these environment variables (CI does the same). `DOTNET_EnableHWIntrinsic=0` works on every architecture; the other switches apply to x86/x64 (on ARM64, use `DOTNET_EnableArm64Aes=0` and `DOTNET_EnableArm64Crc32=0`).

| Variable | Paths exercised |
| --- | --- |
| `DOTNET_EnableHWIntrinsic=0` | Scalar code everywhere |
| `DOTNET_EnableAVX2=0` | SSSE3 / Vector128 paths |
| `DOTNET_EnableSSE42=0` | BCL Base64 encoding path |
| `DOTNET_EnableAES=0` | Software AES (AEGIS) and table-based CRC-32 |

One test needs about 3 GB of memory and runs only on request: `dotnet Test/bin/Release/net10.0/Test.dll -method Test.FastBase64EncodeTest.EncodeToCharsAroundTwoToTheThirtyChars -explicit only`.

Benchmarks use BenchmarkDotNet:

```sh
dotnet run --project Benchmark/Benchmark.csproj -c Release -- --filter '*HashBenchmark*'
```

The tables in [doc/BenchmarkResults.md](doc/BenchmarkResults.md) and [HashBenchmark.md](HashBenchmark.md) were measured on older hardware and older implementations; they are historical, not current results.

## Migration and license

Public API names were changed to follow .NET naming guidelines (for example, `Base64` became `FastBase64` and `RandomUInt64` became `RandomUInt64Base`). See [Arc.Crypto Name Changes](doc/Arc.Crypto%20Name%20Changes.md) for the complete list and migration steps.

Arc.Crypto is licensed under the [MIT License](LICENSE).
