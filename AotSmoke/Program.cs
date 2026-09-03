// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Arc.Crypto;
using Arc.Crypto.EC;

Check(!RuntimeFeature.IsDynamicCodeSupported, "The executable must be published with Native AOT.");
CheckBlake3();
CheckSodium();
CheckManagedAlgorithms();
Console.WriteLine("Native AOT checks passed: BLAKE3, libsodium, encryption, signatures, hashes, encoding and random generators.");

static void CheckBlake3()
{
    var expected = Convert.FromHexString("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    Equal(expected, Blake3.Get256_ByteArray(ReadOnlySpan<byte>.Empty), "BLAKE3 empty vector");
    using var hasher = Blake3Hasher.New();
    hasher.Update(ReadOnlySpan<byte>.Empty);
    var output = new byte[32];
    hasher.Finalize(output);
    Equal(expected, output, "BLAKE3 incremental empty vector");

    var data = new byte[1025];
    for (var i = 0; i < data.Length; i++)
    {
        data[i] = (byte)(i % 251);
    }

    expected = Convert.FromHexString("d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444");
    Equal(expected, Blake3.Get256_ByteArray(data), "BLAKE3 1025-byte vector");
    hasher.Update(data);
    hasher.Finalize(output);
    Equal(expected, output, "BLAKE3 incremental vector");
    Check(hasher.Finalize().Equals(Blake3.Get256_Struct(data)), "BLAKE3 struct output");

    hasher.Reset();
    hasher.UpdateWithJoin(data);
    hasher.Finalize(output);
    Equal(expected, output, "BLAKE3 parallel update");
    var extended = new byte[4096];
    hasher.Finalize(extended);
    Equal(expected, extended.AsSpan(0, 32), "BLAKE3 extended output");
    hasher.Finalize(Span<byte>.Empty);

    ulong[] words = [1, 2, 3, 4];
    hasher.Reset();
    hasher.Update<ulong>(words);
    hasher.Finalize(output);
    Equal(Blake3.Get256_ByteArray(MemoryMarshal.AsBytes(words.AsSpan())), output, "BLAKE3 generic update");
    hasher.Reset();
    hasher.UpdateWithJoin<ulong>(words);
    hasher.Finalize(output);
    Equal(Blake3.Get256_ByteArray(MemoryMarshal.AsBytes(words.AsSpan())), output, "BLAKE3 generic parallel update");

    // Official test vectors use this 32-byte ASCII key and context.
    using var keyed = Blake3Hasher.NewKeyed("whats the Elvish word for friend"u8);
    keyed.Finalize(output);
    Equal(Convert.FromHexString("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"), output, "BLAKE3 keyed vector");
    using var derived = Blake3Hasher.NewDeriveKey("BLAKE3 2019-12-27 16:29:52 test vectors context");
    derived.Finalize(output);
    Equal(Convert.FromHexString("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"), output, "BLAKE3 derivation vector");

    var uninitialized = default(Blake3Hasher);
    Throws<NullReferenceException>(() => uninitialized.Finalize(), "BLAKE3 invalid state");
}

static void CheckSodium()
{
    var message = "Native AOT message"u8.ToArray();
    var nonce = new byte[CryptoSecretBox.NonceSize];
    var key = new byte[CryptoSecretBox.KeySize];
    CryptoSecretBox.CreateKey(key);
    CryptoRandom.NextBytes(nonce);
    var ciphertext = new byte[message.Length + CryptoSecretBox.MacSize];
    var plaintext = new byte[message.Length];
    CryptoSecretBox.Encrypt(message, nonce, key, ciphertext);
    Check(CryptoSecretBox.TryDecrypt(ciphertext, nonce, key, plaintext), "SecretBox decrypt");
    Equal(message, plaintext, "SecretBox plaintext");
    ciphertext[0] ^= 1;
    Check(!CryptoSecretBox.TryDecrypt(ciphertext, nonce, key, plaintext), "SecretBox tampering");

    var secretKey = new byte[CryptoSign.SecretKeySize];
    var publicKey = new byte[CryptoSign.PublicKeySize];
    var signature = new byte[CryptoSign.SignatureSize];
    CryptoSign.CreateKey(secretKey, publicKey);
    CryptoSign.Sign(message, secretKey, signature);
    Check(CryptoSign.Verify(message, publicKey, signature), "Ed25519 signature");
    signature[0] ^= 1;
    Check(!CryptoSign.Verify(message, publicKey, signature), "Ed25519 tampering");
    var ph = Ed25519ph.New();
    ph.Update(message.AsSpan(0, 5));
    ph.Update(message.AsSpan(5));
    ph.FinalizeAndSign(secretKey, signature);
    ph.Update(message);
    Check(ph.FinalizeAndVerify(publicKey, signature), "Ed25519ph signature and reset");

    var aliceSecret = new byte[CryptoBox.SecretKeySize];
    var alicePublic = new byte[CryptoBox.PublicKeySize];
    var bobSecret = new byte[CryptoBox.SecretKeySize];
    var bobPublic = new byte[CryptoBox.PublicKeySize];
    CryptoBox.CreateKey(aliceSecret, alicePublic);
    CryptoBox.CreateKey(bobSecret, bobPublic);
    CryptoBox.Encrypt(message, nonce, aliceSecret, bobPublic, ciphertext);
    Check(CryptoBox.TryDecrypt(ciphertext, nonce, bobSecret, alicePublic, plaintext), "CryptoBox decrypt");
    Equal(message, plaintext, "CryptoBox plaintext");
    var aliceMaterial = new byte[32];
    var bobMaterial = new byte[32];
    CryptoBox.DeriveKeyMaterial(aliceSecret, bobPublic, aliceMaterial);
    CryptoBox.DeriveKeyMaterial(bobSecret, alicePublic, bobMaterial);
    Equal(aliceMaterial, bobMaterial, "X25519 agreement");

    CryptoDual.CreateKey(secretKey, publicKey, aliceSecret, alicePublic);
    var recovered = new byte[32];
    CryptoDual.PublicKey_BoxToSign(alicePublic, recovered);
    Equal(publicKey, recovered, "Dual key conversion");

    var hash = CryptoPasswordHash.GetHashString("password");
    Check(CryptoPasswordHash.VerifyHashString(hash, "password"), "Argon2id verify");
    Check(!CryptoPasswordHash.VerifyHashString(hash, "wrong"), "Argon2id wrong password");
    Throws<CryptographicException>(() => CryptoPasswordHash.GetHashString("password", memLimit: 0), "Argon2id failure");
    PasswordEncryption.Encrypt(message, "password", out var encrypted);
    Check(PasswordEncryption.TryDecrypt(encrypted, "password", out var decrypted), "Password encryption");
    Equal(message, decrypted, "Password plaintext");
    Check(!PasswordEncryption.TryDecrypt(encrypted, "wrong", out _), "Password encryption rejection");

    Equal(Convert.FromHexString("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
        Blake2B.Get256_ByteArray(ReadOnlySpan<byte>.Empty), "BLAKE2b empty vector");
}

static void CheckManagedAlgorithms()
{
    var message = "Native AOT managed algorithms"u8.ToArray();
    var key = new byte[32];
    var nonce = new byte[32];
    RandomVault.Default.NextBytes(key);
    RandomVault.Libsodium.NextBytes(nonce);
    var cipher = new byte[message.Length + 16];
    var plaintext = new byte[message.Length];
    Aegis256.Encrypt(cipher, message, nonce, key, "associated"u8);
    Check(Aegis256.TryDecrypt(plaintext, cipher, nonce, key, "associated"u8), "AEGIS-256 decrypt");
    Equal(message, plaintext, "AEGIS-256 plaintext");
    cipher[0] ^= 1;
    Check(!Aegis256.TryDecrypt(plaintext, cipher, nonce, key, "associated"u8), "AEGIS-256 tampering");
    Aegis128L.Encrypt(cipher, message, nonce.AsSpan(0, 16), key.AsSpan(0, 16));
    Check(Aegis128L.TryDecrypt(plaintext, cipher, nonce.AsSpan(0, 16), key.AsSpan(0, 16)), "AEGIS-128L decrypt");
    Equal(message, plaintext, "AEGIS-128L plaintext");

    Equal(SHA256.HashData(message), Sha2Helper.Get256_ByteArray(message), "SHA-256");
    Equal(Convert.FromHexString("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        Sha3Helper.Get256_ByteArray(ReadOnlySpan<byte>.Empty), "SHA3-256 empty vector");
    IHash[] hashes = [new Sha3_256(), new XxHash64(), new XXHash32(), new Crc32(), new Adler32()];
    foreach (var hash in hashes)
    {
        hash.HashInitialize();
        hash.HashUpdate(message.AsSpan(0, 3));
        hash.HashUpdate(message.AsSpan(3));
        Equal(hash.HashFinal(), hash.GetHash(message), hash.HashName);
    }

    Equal(message, Hex.FromStringToByteArray(Hex.FromByteArrayToString(message)), "Hex");
    Equal(message, Base64.Decode(Base64.EncodeToString(message)), "Base64");
    Equal(message, Base64Url.Decode(Base64Url.EncodeToString(message)), "Base64Url");
    Equal(message, Base32Sort.Default.FromStringToByteArray(Base32Sort.Default.FromByteArrayToString(message)), "Base32");
    var first = new Xoshiro256StarStar(42);
    var second = new Xoshiro256StarStar(42);
    Check(first.NextUInt64() == second.NextUInt64(), "Seeded random");
    new MersenneTwister(42).NextBytes(plaintext);

    // Standard generator points avoid platform-specific ECDsa curve availability.
    CheckPoint(P256K1Curve.Instance,
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    CheckPoint(P256R1Curve.Instance,
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
}

static void CheckPoint(ECCurveBase curve, string xHex, string yHex)
{
    var x = Convert.FromHexString(xHex);
    var y = Convert.FromHexString(yHex);
    Equal(y, curve.TryDecompressY(x, curve.CompressY(y)), curve.CurveName);
}

static void Equal(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string name)
    => Check(expected.SequenceEqual(actual), name);

static void Check(bool condition, string name)
{
    if (!condition)
    {
        throw new InvalidOperationException(name);
    }
}

static void Throws<T>(Action action, string name)
    where T : Exception
{
    try
    {
        action();
    }
    catch (T)
    {
        return;
    }

    throw new InvalidOperationException(name);
}
