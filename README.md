# Arc.Crypto

Arc.Crypto provides cryptographic primitives, fast hashes, random generators, and encoders for .NET 10.

| Area | Implementations |
| --- | --- |
| Authenticated encryption | AEGIS-256, AEGIS-128L, XSalsa20-Poly1305 (`CryptoSecretBox`) |
| Passwords | `PasswordEncryption`, Argon2id derivation and password hashes (`CryptoPasswordHash`) |
| Public keys | Ed25519, Ed25519ph, X25519 authenticated encryption and raw key agreement |
| Elliptic curve helpers | secp256k1 and secp256r1 field arithmetic, seed validation, point compression |
| Cryptographic hashes | BLAKE3, BLAKE2b, SHA-2, SHA-3; a legacy SHA-1 wrapper |
| Non-cryptographic hashes | FarmHash64, xxHash3, xxHash32/64, Adler-32, CRC-32 |
| Random data | xoshiro256**, xoroshiro128**, Xorshift, MT19937-64, `AegisRandom`, `RandomVault` |
| Encoding and comparison | Hex, Base64, Base64Url, sortable Base32, UTF-8/UTF-16 array comparers |

## Installation and native dependencies

```sh
dotnet add package Arc.Crypto
```

```csharp
using Arc.Crypto;
```

Libsodium supplies native password hashing, signatures, public-key encryption, and BLAKE2b. BLAKE3 uses `blake3_dotnet`. NuGet selects native assets by runtime identifier (RID); BLAKE3 assets also propagate through project references. Deploy the complete output directory with its shared libraries.

Managed AEGIS selects x86 AES, ARM AES, or its software implementation at runtime. Base64 selects x86 SIMD or scalar code. Non-cryptographic hashes, SHA-3, and the seeded pseudo-random generators do not require either native library.

Native AOT and trimming analysis are enabled. CI validates Windows x64 and Linux x64, using both project references and NuGet packages. Other RIDs require separate execution validation. See [Native AOT verification](doc/NativeAOT.md).

## Encryption

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

AEGIS-256 uses a 32-byte key and nonce; AEGIS-128L uses 16 bytes each. Tags are 16 bytes by default or 32 bytes when requested. A tag size of zero disables authentication and tamper detection. Authentication failure returns `false` and clears the plaintext buffer. Invalid lengths throw. In-place operation requires the plaintext and ciphertext spans to start at the same address; shifted overlaps are unsupported.

Never reuse a nonce with the same key. Store or transmit the nonce alongside the ciphertext, and supply the same associated data when decrypting.

```csharp
Span<byte> key = stackalloc byte[CryptoSecretBox.KeySize];
Span<byte> nonce = stackalloc byte[CryptoSecretBox.NonceSize];
CryptoSecretBox.CreateKey(key);
CryptoRandom.NextBytes(nonce);
var cipher = new byte[message.Length + CryptoSecretBox.MacSize];
CryptoSecretBox.Encrypt(message, nonce, key, cipher);
bool valid = CryptoSecretBox.TryDecrypt(cipher, nonce, key, plaintext);
```

`CryptoSecretBox` uses a 32-byte key, 24-byte nonce, and 16-byte MAC. Its output contains the MAC followed by the encrypted message. Always check the decryption result before using the output.

### Password encryption and hashing

```csharp
PasswordEncryption.Encrypt("Message"u8, "correct", out var encrypted);
bool valid = PasswordEncryption.TryDecrypt(encrypted, "correct", out var decrypted);
bool invalid = PasswordEncryption.TryDecrypt(encrypted, "incorrect", out _); // false

string storedHash = CryptoPasswordHash.GetHashString("password");
bool matches = CryptoPasswordHash.VerifyHashString(storedHash, "password");
```

`PasswordEncryption` stores `[salt/nonce: 32 bytes][ciphertext][tag: 16 bytes]`, adding 48 bytes to the plaintext. Non-empty passwords use Argon2id with the interactive cost and AEGIS-256. For compatibility, an empty password uses the public salt as the key: this provides no confidentiality or protection against forgery. Use a non-empty password for protected data.

Span overloads accept an exactly sized destination; UTF-8 password overloads avoid text conversion. String overloads use stack storage for short UTF-8 passwords and pooled storage for longer ones, clearing temporary password bytes and derived keys after use. Array overloads allocate their result. The format contains no version or cost metadata.

`CryptoPasswordHash.DeriveKey` accepts a 16-byte salt and an output of at least 16 bytes. Its `OpsLimit` and `MemLimit` parameters control Argon2id cost; interactive memory is 64 MiB. Password hash strings contain their salt and cost parameters. The optional cost arguments on `VerifyHashString` are retained for compatibility and ignored. Native Argon2 memory is separate from managed allocation measurements.

## Public keys

```csharp
Span<byte> secretKey = stackalloc byte[CryptoSign.SecretKeySize];
Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeySize];
Span<byte> signature = stackalloc byte[CryptoSign.SignatureSize];
CryptoSign.CreateKey(secretKey, publicKey);
CryptoSign.Sign("Message"u8, secretKey, signature);
bool valid = CryptoSign.Verify("Message"u8, publicKey, signature);

var ph = Ed25519ph.New();
ph.Update("Mes"u8);
ph.Update("sage"u8);
ph.FinalizeAndSign(secretKey, signature);
```

Ed25519 uses a 32-byte seed, 64-byte secret key, 32-byte public key, and 64-byte signature. `Ed25519ph` signs message fragments and resets after final signing or verification. Ed25519ph signatures differ from ordinary Ed25519 signatures.

`CryptoBox` combines X25519 with XSalsa20-Poly1305. Encrypt with the sender's secret key and recipient's public key; decrypt with the recipient's secret key and sender's public key. Keys and seeds are 32 bytes, nonces are 24 bytes, and the MAC is 16 bytes. Encryption and raw key agreement throw `CryptographicException` for public keys rejected by Libsodium.

`CryptoBox.DeriveKeyMaterial` returns a raw X25519 shared secret. Apply a KDF that binds both public keys in a consistent order and the protocol context before using it as a session key. See [Libsodium's key agreement guidance](https://doc.libsodium.org/advanced/scalar_multiplication).

`CryptoDual` derives signing and encryption keys from one seed and converts between their public keys. It stores an extra sign bit in the encryption public key, so this representation is not the standard X25519 key format. `BoxPublicKey_Equals` ignores that bit; conversion alone does not validate a public key.

The `Arc.Crypto.EC` namespace exposes `P256K1Curve.Instance` and `P256R1Curve.Instance`. These provide field operations and point compression, rather than ECDSA signing. Coordinates are big-endian. `TryDecompressY` rejects coordinates outside the field. `IsValidSeed` checks size, range, and a bit-variation heuristic; it is stricter than mathematical private-key validity and does not measure entropy. Treat the exposed curve parameter arrays as read-only.

## Hashing

```csharp
ReadOnlySpan<byte> data = "Message"u8;
ulong fastHash = XxHash3.Hash64(data);
ulong farmHash = FarmHash.Hash64(data);
ulong xxHash = XxHash64.Hash64(data);
uint checksum = Crc32.Hash32(data);

Span<byte> digest = stackalloc byte[32];
Blake3.Get256_Span(data, digest);
Blake2B.Get256_Span(data, digest);
Sha2Helper.Get256_Span(data, digest);
Sha3Helper.Get256_Span(data, digest);

using var hasher = Blake3Hasher.New();
hasher.Update(data);
hasher.Finalize(digest);
```

Static span hashing avoids a result allocation. SHA-2 reuses pooled hash instances, which may allocate on pool misses. BLAKE2b and BLAKE3 fixed-size span methods require an exact output size; SHA-2 and SHA-3 accept larger buffers and leave trailing bytes unchanged. Array methods allocate an output array. Tuple methods interpret digest bytes as unsigned 64-bit words in native byte order; serialize digest bytes for portable interchange.

`Blake3Hasher` supports keyed hashing, context-based key derivation, reset, parallel updates (`UpdateWithJoin`), and arbitrary-length output. Derivation contexts identify the application; append secret key material with `Update`. The hasher owns native state: dispose it, do not copy an initialized struct, and do not use it concurrently. Finalization is repeatable and does not reset the state.

`IHash` provides `HashInitialize`, `HashUpdate`, and `HashFinal` for xxHash32/64, Adler-32, CRC-32, and the SHA wrappers. Initialize each new incremental calculation explicitly; reset behavior after finalization varies. `HashFinal` returns an allocated array. SHA-3 also has span output. Dispose the SHA-1/SHA-2 wrappers. Incremental FarmHash uses its separate stack-based `Initialize`/`Append`/`Finalize` API.

String hashing overloads hash the native UTF-16 representation, not UTF-8. Non-cryptographic hashes and checksums are unsuitable for authentication. SHA-1 is retained for compatibility. Performance depends on input size, processor, and algorithm; there is no universal 32-bit versus 64-bit ranking.

## Random data

```csharp
var random = new Xoshiro256StarStar(42);
ulong value = random.NextUInt64();
int index = random.NextInt32(0, 100); // [0, 100)
double fraction = random.NextDouble(); // [0, 1)
var bytes = new byte[16];
random.NextBytes(bytes);

RandomVault.Default.NextBytes(bytes);
ulong secureValue = RandomVault.Default.NextUInt64();
ulong fastValue = RandomVault.Xoshiro.NextUInt64();
```

xoshiro256**, xoroshiro128**, Xorshift, and Mersenne Twister are deterministic, not cryptographically secure, and not thread-safe. They derive from `RandomUInt64`. Unbounded `NextInt32()` and `NextInt64()` include negative values; `NextInt31()` and `NextInt63()` return non-negative values. Bounded methods use an exclusive upper bound, reject inverted ranges, and return the lower bound when both bounds are equal. Single-bound overloads require a non-negative upper bound. Mersenne Twister byte-array seeds must be non-empty and contain complete 64-bit words in native byte order.

`Arc.Crypto.Random.AegisRandom` combines the operating system RNG with AEGIS-256 and exposes `NextBytes`; it does not derive from `RandomUInt64`. It is not thread-safe. `CryptoRandom` directly wraps Libsodium randomness.

`RandomVault` serializes calls to a supplied generator and buffers random bytes. `Default` aliases `Aegis`; `Xoshiro` is non-cryptographic, while `Libsodium` and `RandomNumberGenerator` wrap the respective secure generators. A custom vault accepts `Action<Span<byte>>` and a non-negative bypass threshold. Avoid calling a wrapped mutable generator outside the vault concurrently.

## Encoding and comparison

```csharp
byte[] data = [0, 1, 2, 3];
string hex = Hex.FromByteArrayToString(data); // "00010203"
string base64 = Base64.EncodeToString(data); // "AAECAw=="
string url = Base64Url.EncodeToString(data); // "AAECAw"
string base32 = Base32Sort.Default.FromByteArrayToString(data); // "000H40S"
```

Base64 and Base64Url encode UTF-8/ASCII bytes or UTF-16 characters into caller-supplied spans. Decoding accepts padded or unpadded input, rejects whitespace and the wrong alphabet, and reports failure through `TryDecode`. On failure the destination may be partially written and `bytesWritten` is zero. Length helpers size buffers; `GetDecodedLength` inspects length and trailing padding without fully validating the alphabet.

Base32Sort uses `0123456789ABCEFGHJKMNPQRSTUVWXYZ`, preserves byte sort order with ordinal string comparison, and emits no padding. Decoding accepts lower-case letters, maps `I`/`i`/`l` to `1` and `O`/`o` to `0`; upper-case `L` is rejected. `Default` aliases the table converter; `Reference` supplies an alternative implementation. Span decoders return `false` on invalid input; array decoders return an empty array, which also represents valid empty input. Prefer span decoding when that distinction matters. Length helpers reject negative input and encoding overflow.

Hex output is lower-case. `Hex.FromStringToByteArray` requires an even length but deliberately does not validate characters; invalid digits produce unspecified bytes.

`Utf8StringEqualityComparer` and `Utf16StringEqualityComparer` compare arrays by content and support allocation-free alternate span lookups in `Dictionary`. They perform ordinal comparison without case folding or Unicode normalization. Inserting a new span key copies it into an owned array. Do not mutate an array used as a dictionary key.

## Tests and performance

```sh
dotnet build Arc.Crypto.slnx -c Release
dotnet test --project Test/Test.csproj -c Release
dotnet run --project Benchmark/Benchmark.csproj -c Release -- --filter '*AllocationBenchmark*' --job short
```

Tests cover known answers, incremental and one-shot equivalence, malformed input, buffer boundaries, authentication failures, and allocation regressions. See [review and coverage results](doc/CodeReview.md) for measured coverage, remaining platform gaps, and reproduction commands. Allocation checks cover managed memory after warmup; native memory and pool growth are separate costs.

Historical benchmark tables are preserved in [HistoricalBenchmarks.md](doc/HistoricalBenchmarks.md). They describe older hardware and implementations and are not current performance guarantees.
