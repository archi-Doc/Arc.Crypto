# Arc.Crypto Name Changes

Public API names were changed to follow .NET naming guidelines and to remove conflicts with BCL types. **Behavior is unchanged.** Every rename is source- and binary-breaking, so dependent projects must be updated and recompiled.

## How to migrate

1. Replace `using Arc.Crypto.Random;` with `using Arc.Crypto;` (or delete it if `using Arc.Crypto;` is already present).
2. Apply the [bulk replacements](#bulk-replacements-regex) below.
3. Apply the [manual replacements](#manual-replacements) below. These cannot be matched safely by a regex.
4. Rebuild. Remaining errors usually come from [named arguments](#parameters) or derived classes.

## Types

| Old | New | Notes |
| --- | --- | --- |
| `Base64` | `FastBase64` | Avoids the conflict with `System.Buffers.Text.Base64`. |
| `Base64Url` | `FastBase64Url` | Avoids the conflict with `System.Buffers.Text.Base64Url`. |
| `XXHash32` | `XxHash32` | Matches `XxHash64` and `XxHash3`. If `System.IO.Hashing` is also imported, qualify as `Arc.Crypto.XxHash32`. |
| `InternalXXHash` | `XxHashBase` | Base class of `XxHash32` and `XxHash64`. |
| `Arc.Crypto.EC.P256K1Curve` | `Arc.Crypto.EC.Secp256k1Curve` | |
| `Arc.Crypto.EC.P256R1Curve` | `Arc.Crypto.EC.Secp256r1Curve` | |
| `RandomUInt64` | `RandomUInt64Base` | Update classes that derive from it. |
| `CryptoPasswordHash.OpsLimit` | `CryptoPasswordHash.OperationLimit` | Enum values are unchanged. |
| `CryptoPasswordHash.MemLimit` | `CryptoPasswordHash.MemoryLimit` | Enum values are unchanged. |

## Namespaces

| Old | New | Notes |
| --- | --- | --- |
| `Arc.Crypto.Random.AegisRandom` | `Arc.Crypto.AegisRandom` | The `Arc.Crypto.Random` namespace was removed. |

## Members

| Type | Old | New | Notes |
| --- | --- | --- | --- |
| `Blake3Hasher` | `Finalize()` | `FinalizeHash()` | Avoids the clash with `Object.Finalize`. |
| `Blake3Hasher` | `Finalize(Span<byte>)` | `FinalizeHash(Span<byte>)` | |
| `Blake3Hasher` | `UpdateWithJoin`, `UpdateWithJoin<T>` | `UpdateParallel`, `UpdateParallel<T>` | |
| `FarmHash` | `Initialize()` | `Reset()` | Matches `XxHash3.Reset` and `Blake3Hasher.Reset`. |
| `FarmHash` | `Finalize()` | `FinalizeHash()` | |
| `Blake3` | `Size` | `HashLength` | Matches other hash classes. |
| `Blake2B`, `Blake3`, `Sha2Helper`, `Sha3Helper` | `GetNNN_ByteArray`, `GetNNN_Span`, `GetNNN_UInt64`, `GetNNN_Struct` | `GetNNNByteArray`, `GetNNNSpan`, `GetNNNUInt64`, `GetNNNStruct` | `NNN` is `256`, `384` or `512`, as available on each class. |
| `Sha2Helper` | `Get512_Libsodium` | `Get512SpanLibsodium` | |
| `HashAlgorithmWrapper` (`Sha1`, `Sha2_256`, `Sha2_384`, `Sha2_512`) | `EmptyByte` | `EmptyBytes` | |
| `CryptoBox` | `CreateKey` | `CreateKeyPair` | Both overloads. |
| `CryptoBox` | `DeriveKeyMaterial` | `DeriveSharedSecret` | Returns a raw X25519 shared secret, as before. |
| `CryptoBox` | `KeyMaterialSize` | `SharedSecretSize` | |
| `CryptoSign` | `CreateKey` | `CreateKeyPair` | Both overloads. |
| `CryptoDual` | `CreateKey` | `CreateKeyPair` | Both overloads. |
| `CryptoDual` | `SecretKey_SignToBox` | `ConvertSignSecretKeyToBox` | |
| `CryptoDual` | `PublicKey_SignToBox` | `ConvertSignPublicKeyToBox` | |
| `CryptoDual` | `PublicKey_BoxToSign` | `ConvertBoxPublicKeyToSign` | |
| `CryptoDual` | `BoxPublicKey_Equals` | `BoxPublicKeyEquals` | |
| `CryptoPasswordHash` | `GetHashString(ReadOnlySpan<byte>, ...)` | `GetUtf8HashString(ReadOnlySpan<byte>, ...)` | Returns `byte[]`. The `string` overload keeps the name `GetHashString`. |
| `CryptoPasswordHash` | `HashStringLength` | `MaxHashStringLength` | |
| `ECCurveBase` (`Secp256k1Curve`, `Secp256r1Curve`) | `TryDecompressY` | `DecompressY` | Still returns `byte[]?` (`null` on failure). |
| `RandomUInt64Base` (all generators and `RandomVault`) | `NextDouble2` | `NextDoubleInclusive` | Range [0, 1]. |
| `RandomUInt64Base` (all generators and `RandomVault`) | `NextDouble3` | `NextDoubleExclusive` | Range (0, 1). |
| `RandomVault` | `RandomNumberGenerator` (static property) | `SystemRng` | Avoids shadowing `System.Security.Cryptography.RandomNumberGenerator`. |
| `Xorshift` | `Xor32` | `NextState32` | Both overloads. |
| `Xorshift` | `Xor64` | `NextState64` | Both overloads. |
| `MersenneTwister` | `BufferSize` | `StateSize` | |
| `IBase32Converter` (`Base32Sort.Default`, `Reference`, `Table`) | `FromByteArrayToSpan` | `FromBytesToSpan` | Both overloads. |
| `IBase32Converter` | `FromByteArrayToUtf8` | `FromBytesToUtf8` | |
| `IBase32Converter` | `FromByteArrayToString` | `FromBytesToString` | |
| `Hex` | `FromByteArrayToString` | `FromBytesToString` | |

Not renamed: `CryptoSecretBox.CreateKey`, `Hex.FromStringToByteArray`, `IBase32Converter.FromUtf8To*` / `FromStringTo*`, `IHash.HashInitialize`.

## Parameters

These renames only affect callers that use named arguments (for example `memLimit: ...`) and classes that override the member.

| Member | Old | New |
| --- | --- | --- |
| `CryptoPasswordHash.DeriveKey`, `GetHashString`, `GetUtf8HashString`, `VerifyHashString` | `opsLimit`, `memLimit` | `operationLimit`, `memoryLimit` |
| `CryptoBox.Encrypt`, `CryptoSecretBox.Encrypt` | `message`, `cipher` | `plaintext`, `ciphertext` |
| `CryptoBox.TryDecrypt`, `CryptoSecretBox.TryDecrypt` | `cipher`, `message` | `ciphertext`, `plaintext` |
| `CryptoBox.DeriveSharedSecret` | `material` | `sharedSecret` |
| `CryptoDual.BoxPublicKeyEquals` | `publicKey` | `publicKey1` |
| `PasswordEncryption.Encrypt(ReadOnlySpan<byte>, ReadOnlySpan<byte>, out byte[])` | `password` | `utf8Password` |
| `Blake3Hasher.NewDeriveKey(string)` | `text` | `context` |
| `Blake3Hasher.NewDeriveKey(ReadOnlySpan<byte>)` | `input` | `utf8Context` |
| `Blake3Hasher.FinalizeHash(Span<byte>)` | `hash32` | `output` |
| `ECCurveBase.DecompressY` | `y` | `yBit` |
| `Secp256k1Curve.ElementSqrt`, `Secp256r1Curve.ElementSqrt` | `x1` | `x` |
| `Xoshiro256StarStar.NextBytes`, `Xoroshiro128StarStar.NextBytes` | `buffer` | `destination` |
| `CryptoRandom.NextBytes` | `buffer` | `destination` |
| `Hex.FromStringToByteArray` | `str` | `hex` |

## Bulk replacements (regex)

Case-sensitive. Apply in this order to C# files that reference Arc.Crypto.

```text
using Arc\.Crypto\.Random;                              => using Arc.Crypto;
\bXXHash32\b                                            => XxHash32
\bInternalXXHash\b                                      => XxHashBase
\bP256K1Curve\b                                         => Secp256k1Curve
\bP256R1Curve\b                                         => Secp256r1Curve
\bRandomUInt64\b                                        => RandomUInt64Base
\bUpdateWithJoin\b                                      => UpdateParallel
\bDeriveKeyMaterial\b                                   => DeriveSharedSecret
\bKeyMaterialSize\b                                     => SharedSecretSize
\bTryDecompressY\b                                      => DecompressY
\bSecretKey_SignToBox\b                                 => ConvertSignSecretKeyToBox
\bPublicKey_SignToBox\b                                 => ConvertSignPublicKeyToBox
\bPublicKey_BoxToSign\b                                 => ConvertBoxPublicKeyToSign
\bBoxPublicKey_Equals\b                                 => BoxPublicKeyEquals
\bHashStringLength\b                                    => MaxHashStringLength
\bOpsLimit\b                                            => OperationLimit
\bMemLimit\b                                            => MemoryLimit
\bEmptyByte\b                                           => EmptyBytes
\bNextDouble2\b                                         => NextDoubleInclusive
\bNextDouble3\b                                         => NextDoubleExclusive
\bXor32\b                                               => NextState32
\bXor64\b                                               => NextState64
\bGet512_Libsodium\b                                    => Get512SpanLibsodium
\bGet(256|384|512)_(ByteArray|Span|UInt64|Struct)\b     => Get$1$2
\bFromByteArrayTo(Span|Utf8|String)\b                   => FromBytesTo$1
\bRandomVault\.RandomNumberGenerator\b                  => RandomVault.SystemRng
\bBlake3\.Size\b                                        => Blake3.HashLength
\b(CryptoBox|CryptoSign|CryptoDual)\.CreateKey\(        => $1.CreateKeyPair(
```

`FromByteArrayTo*` is only safe as a bulk replacement if your project has no other types that use that method name.

## Manual replacements

Review each match; these patterns also match unrelated code.

| Find | Replace with | Only when |
| --- | --- | --- |
| `Base64.` | `FastBase64.` | The receiver is `Arc.Crypto.Base64` (not `System.Buffers.Text.Base64` or another library). |
| `Base64Url.` | `FastBase64Url.` | The receiver is `Arc.Crypto.Base64Url`. |
| `.Finalize(` | `.FinalizeHash(` | The receiver is a `Blake3Hasher` or `FarmHash`. |
| `.Initialize()` | `.Reset()` | The receiver is a `FarmHash`. |
| `CryptoPasswordHash.GetHashString(` | `CryptoPasswordHash.GetUtf8HashString(` | The argument is UTF-8 bytes (`"..."u8`, `byte[]`, `ReadOnlySpan<byte>`). |
| `opsLimit:` / `memLimit:` | `operationLimit:` / `memoryLimit:` | Named arguments to `CryptoPasswordHash` methods. |
| `message:` / `cipher:` | `plaintext:` / `ciphertext:` | Named arguments to `CryptoBox` or `CryptoSecretBox` methods. |

## Source files (library contributors)

| Old | New |
| --- | --- |
| `Arc.Crypto/Misc/FaseBase64.cs` | `Arc.Crypto/Misc/FastBase64.cs` |
| `Arc.Crypto/Hash/IHashWrapper.cs` | `Arc.Crypto/Hash/HashAlgorithmWrapper.cs` |
| `Arc.Crypto/Signature/P256K1Curve.cs` | `Arc.Crypto/Signature/Secp256k1Curve.cs` |
| `Arc.Crypto/Signature/P256R1Curve.cs` | `Arc.Crypto/Signature/Secp256r1Curve.cs` |
| `Arc.Crypto/Random/RandomUInt64.cs` | `Arc.Crypto/Random/RandomUInt64Base.cs` |
