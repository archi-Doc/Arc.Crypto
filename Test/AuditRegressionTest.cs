// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

/// <summary>
/// Regression tests for defects found while auditing the library: buffer overlap handling,
/// one-shot hashes disturbing incremental state, decoder validation and key conversion.
/// </summary>
public class AuditRegressionTest
{
    private const int MessageLength = 100;

    public static TheoryData<string> HashNames => new() { "SHA1", "SHA2-256", "SHA2-384", "SHA2-512", "SHA3-256", "SHA3-384", "SHA3-512", "xxHash32", "xxHash64", "CRC-32", "Adler-32", };

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(33)]
    public void AegisRejectsOutputStartingAfterOverlappingInput(int shift)
    {
        var key = new byte[Aegis256.KeySize];
        var nonce = new byte[Aegis256.NonceSize];
        var buffer = new byte[MessageLength + shift + Aegis256.MaxTagSize];
        new Xoshiro256StarStar(1).NextBytes(buffer);
        var original = buffer.ToArray();

        // Encryption would have produced a valid tag over already overwritten plaintext.
        Assert.Throws<ArgumentException>(() => Aegis256.Encrypt(buffer.AsSpan(shift, MessageLength + 16), buffer.AsSpan(0, MessageLength), nonce, key));
        Assert.Throws<ArgumentException>(() => Aegis128L.Encrypt(buffer.AsSpan(shift, MessageLength + 16), buffer.AsSpan(0, MessageLength), nonce.AsSpan(0, 16), key.AsSpan(0, 16)));
        Assert.Throws<ArgumentException>(() => Aegis256.TryDecrypt(buffer.AsSpan(shift, MessageLength), buffer.AsSpan(0, MessageLength + 16), nonce, key));
        Assert.Throws<ArgumentException>(() => Aegis128L.TryDecrypt(buffer.AsSpan(shift, MessageLength), buffer.AsSpan(0, MessageLength + 16), nonce.AsSpan(0, 16), key.AsSpan(0, 16)));
        Assert.Equal(original, buffer); // Rejected before anything is written.
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 0)]
    [InlineData(16, 32)]
    [InlineData(33, 16)]
    public void AegisSupportsSameAddressAndOutputBeforeInput(int shift, int tagSize)
    {
        var random = new Xoshiro256StarStar(2);
        var key = new byte[Aegis256.KeySize];
        var nonce = new byte[Aegis256.NonceSize];
        var message = new byte[MessageLength];
        random.NextBytes(key);
        random.NextBytes(nonce);
        random.NextBytes(message);

        foreach (var variant in new[] { 128, 256 })
        {
            var keySpan = variant == 128 ? key.AsSpan(0, 16).ToArray() : key;
            var nonceSpan = variant == 128 ? nonce.AsSpan(0, 16).ToArray() : nonce;
            var expected = new byte[MessageLength + tagSize];
            Encrypt(variant, expected, message, nonceSpan, keySpan, tagSize);

            // Ciphertext written at or before the plaintext it reads.
            var buffer = new byte[shift + MessageLength + tagSize];
            message.CopyTo(buffer, shift);
            Encrypt(variant, buffer.AsSpan(0, MessageLength + tagSize), buffer.AsSpan(shift, MessageLength), nonceSpan, keySpan, tagSize);
            Assert.Equal(expected, buffer.AsSpan(0, MessageLength + tagSize).ToArray());

            // Plaintext written at or before the ciphertext it reads.
            buffer = new byte[shift + MessageLength + tagSize];
            expected.CopyTo(buffer, shift);
            Assert.True(TryDecrypt(variant, buffer.AsSpan(0, MessageLength), buffer.AsSpan(shift, MessageLength + tagSize), nonceSpan, keySpan, tagSize));
            Assert.Equal(message, buffer.AsSpan(0, MessageLength).ToArray());

            // The portable backends must behave the same way as the hardware ones selected above.
            buffer = new byte[shift + MessageLength + tagSize];
            message.CopyTo(buffer, shift);
            if (variant == 128)
            {
                Aegis128LSoft.Encrypt(buffer.AsSpan(0, MessageLength + tagSize), buffer.AsSpan(shift, MessageLength), nonceSpan, keySpan, default, tagSize);
            }
            else
            {
                Aegis256Soft.Encrypt(buffer.AsSpan(0, MessageLength + tagSize), buffer.AsSpan(shift, MessageLength), nonceSpan, keySpan, default, tagSize);
            }

            Assert.Equal(expected, buffer.AsSpan(0, MessageLength + tagSize).ToArray());
        }
    }

    [Fact]
    public void PasswordEncryptionInPlaceAndOverlap()
    {
        // An empty password skips Argon2id, which keeps the test fast; overlap handling does not depend on the key.
        var message = Enumerable.Range(0, MessageLength).Select(x => (byte)x).ToArray();
        var buffer = new byte[PasswordEncryption.SaltSize + MessageLength + PasswordEncryption.TagSize];
        message.CopyTo(buffer, PasswordEncryption.SaltSize);
        PasswordEncryption.Encrypt(buffer.AsSpan(PasswordEncryption.SaltSize, MessageLength), ReadOnlySpan<byte>.Empty, buffer);
        Assert.True(PasswordEncryption.TryDecrypt(buffer, ReadOnlySpan<byte>.Empty, out var decrypted));
        Assert.Equal(message, decrypted);

        // Decrypting in place onto the salt is fine: the salt is consumed before any plaintext is written.
        Assert.True(PasswordEncryption.TryDecrypt(buffer, ReadOnlySpan<byte>.Empty, buffer.AsSpan(0, MessageLength)));
        Assert.Equal(message, buffer.AsSpan(0, MessageLength).ToArray());

        // Plaintext at the start of the output would be overwritten by the salt before being read.
        foreach (var offset in new[] { 0, 1, PasswordEncryption.SaltSize - 1 })
        {
            buffer = new byte[PasswordEncryption.SaltSize + MessageLength + PasswordEncryption.TagSize];
            message.CopyTo(buffer, offset);
            Assert.Throws<ArgumentException>(() => PasswordEncryption.Encrypt(buffer.AsSpan(offset, MessageLength), ReadOnlySpan<byte>.Empty, buffer));
            Assert.Equal(message, buffer.AsSpan(offset, MessageLength).ToArray());
        }

        // A null password is rejected regardless of the ciphertext length.
        Assert.Throws<ArgumentNullException>(() => PasswordEncryption.TryDecrypt(new byte[47], (string)null!, out _));
        Assert.Throws<ArgumentNullException>(() => PasswordEncryption.TryDecrypt(new byte[48], (string)null!, out _));
    }

    [Fact]
    public void AegisRandomOutputIsUniformAcrossRefills()
    {
        var random = new AegisRandom();
        var output = new byte[65536];
        var position = 0;
        foreach (var size in new[] { 1, 7, 1023, 1024, 1025, 3000 })
        {// Cross the 1024-byte refill boundary at different offsets.
            random.NextBytes(output.AsSpan(position, size));
            position += size;
        }

        random.NextBytes(output.AsSpan(position));
        var counts = new int[256];
        foreach (var x in output)
        {
            counts[x]++;
        }

        // Expected 256 per value with a standard deviation of 16; the bounds are over six deviations wide.
        Assert.All(counts, count => Assert.InRange(count, 150, 362));
    }

    [Fact]
    public void Base64DecodeLeavesBytesAfterOutputUntouched()
    {
        const byte Marker = 0xA5;
        var random = new Xoshiro256StarStar(3);
        for (var length = 0; length <= 300; length++)
        {
            var data = new byte[length];
            random.NextBytes(data);
            var base64 = Convert.ToBase64String(data);
            var base64Url = FastBase64Url.EncodeToString(data);
            var destination = new byte[length + 64];

            for (var variant = 0; variant < 4; variant++)
            {
                destination.AsSpan().Fill(Marker);
                var written = -1;
                var result = variant switch
                {
                    0 => FastBase64.TryDecode(base64.AsSpan(), destination, out written),
                    1 => FastBase64.TryDecode(Encoding.ASCII.GetBytes(base64), destination, out written),
                    2 => FastBase64Url.TryDecode(base64Url.AsSpan(), destination, out written),
                    _ => FastBase64Url.TryDecode(Encoding.ASCII.GetBytes(base64Url), destination, out written),
                };

                Assert.True(result);
                Assert.Equal(length, written);
                Assert.Equal(data, destination.AsSpan(0, length).ToArray());
                Assert.True(destination.AsSpan(length).IndexOfAnyExcept(Marker) < 0, $"Length {length}, variant {variant} wrote past bytesWritten.");
            }
        }
    }

    [Theory]
    [InlineData("ŁŁ")] // Low byte 0x41 ('A').
    [InlineData("İİ")] // Low byte 0x30 ('0').
    [InlineData("ĀĀ")]
    [InlineData("0000000Ł")]
    [InlineData("İ0000000")]
    [InlineData("000000000000Ł")]
    [InlineData("!")]
    [InlineData("00000000!")]
    [InlineData("000000000000000İ")]
    public void Base32RejectsInvalidCharacters(string base32)
    {
        var destination = new byte[16];
        foreach (var converter in new[] { Base32Sort.Table, Base32Sort.Reference })
        {
            Assert.False(converter.FromStringToSpan(base32, destination, out var written));
            Assert.Equal(0, written);
            Assert.Empty(converter.FromStringToByteArray(base32));
        }
    }

    [Fact]
    public void Base32TableAgreesWithReference()
    {
        const string Symbols = "0123456789ABCEFGHJKMNPQRSTUVWXYZabcefghjkmnpqrstuvwxyzIilOo";
        var random = new Xoshiro256StarStar(4);
        var expected = new byte[16];
        var actual = new byte[16];
        for (var i = 0; i < 20_000; i++)
        {
            var length = random.NextInt32(0, 18);
            var chars = new char[length];
            for (var j = 0; j < length; j++)
            {
                var r = random.NextInt32(0, 64);
                chars[j] = r switch
                {
                    < 58 => Symbols[r],
                    58 => '!',
                    59 => 'L',
                    60 => (char)0x141,
                    61 => (char)0x130,
                    62 => (char)0xFF,
                    _ => (char)0x80,
                };
            }

            var expectedResult = Base32Sort.Reference.FromStringToSpan(chars, expected, out var expectedWritten);
            var actualResult = Base32Sort.Table.FromStringToSpan(chars, actual, out var actualWritten);
            Assert.Equal(expectedResult, actualResult);
            Assert.Equal(expectedWritten, actualWritten);
            Assert.Equal(expected.AsSpan(0, expectedWritten).ToArray(), actual.AsSpan(0, actualWritten).ToArray());

            if (chars.All(c => c <= 0xFF))
            {
                var utf8 = chars.Select(c => (byte)c).ToArray();
                expectedResult = Base32Sort.Reference.FromUtf8ToSpan(utf8, expected, out expectedWritten);
                actualResult = Base32Sort.Table.FromUtf8ToSpan(utf8, actual, out actualWritten);
                Assert.Equal(expectedResult, actualResult);
                Assert.Equal(expectedWritten, actualWritten);
                Assert.Equal(expected.AsSpan(0, expectedWritten).ToArray(), actual.AsSpan(0, actualWritten).ToArray());
            }
        }
    }

    [Fact]
    public void HexRejectsInvalidInput()
    {
        Assert.Throws<ArgumentNullException>(() => Hex.FromStringToByteArray(null!));
        Assert.Throws<FormatException>(() => Hex.FromStringToByteArray("zz"));
        Assert.Throws<FormatException>(() => Hex.FromStringToByteArray("0x"));
        Assert.Throws<FormatException>(() => Hex.FromStringToByteArray("::"));
        Assert.Empty(Hex.FromStringToByteArray(string.Empty));
    }

    [Theory]
    [MemberData(nameof(HashNames))]
    public void GetHashDoesNotDisturbIncrementalHash(string name)
    {
        var random = new Xoshiro256StarStar(5);
        var a = new byte[200];
        var b = new byte[77];
        var c = new byte[150];
        random.NextBytes(a);
        random.NextBytes(b);
        random.NextBytes(c);

        var hash = CreateHash(name);
        var reference = CreateHash(name);
        try
        {
            hash.HashInitialize();
            hash.HashUpdate(a);
            Assert.Equal(reference.GetHash(b), hash.GetHash(b));
            Assert.Equal(reference.GetHash(b), hash.GetHash(b, 0, b.Length));
            hash.HashUpdate(c);
            Assert.Equal(reference.GetHash(a.Concat(c).ToArray()), hash.HashFinal());
        }
        finally
        {
            (hash as IDisposable)?.Dispose();
            (reference as IDisposable)?.Dispose();
        }
    }

    [Fact]
    public void Sha3UInt64OverloadsDoNotDisturbIncrementalHash()
    {
        var a = Enumerable.Range(0, 300).Select(x => (byte)x).ToArray();
        var b = "b"u8.ToArray();
        var hash = new Sha3_256();
        hash.HashUpdate(a);
        Assert.Equal(Sha3Helper.Get256UInt64(b), hash.GetHashUInt64(b));
        Assert.Equal(Sha3Helper.Get256UInt64(b), hash.GetHashUInt64(b, 0, b.Length));
        hash.HashUpdate(b);
        Assert.Equal(Sha3Helper.Get256UInt64(a.Concat(b).ToArray()), hash.HashFinalUInt64());
        Assert.Equal(Sha3Helper.Get256UInt64(ReadOnlySpan<byte>.Empty), hash.HashFinalUInt64()); // Reset after finalization.
    }

    [Fact]
    public void XxHashWorksWithoutExplicitInitialization()
    {
        var data = Enumerable.Range(0, 100).Select(x => (byte)x).ToArray();
        var xx64 = new XxHash64();
        xx64.HashUpdate(data);
        Assert.Equal(xx64.GetHash(data), xx64.HashFinal());

        var xx32 = new XxHash32();
        xx32.HashUpdate(data);
        Assert.Equal(xx32.GetHash(data), xx32.HashFinal());
    }

    [Fact]
    public void Crc32MatchesSystemIOHashing()
    {
        var random = new Xoshiro256StarStar(6);
        var data = new byte[5000];
        random.NextBytes(data);
        var crc = new Arc.Crypto.Crc32();
        foreach (var length in Enumerable.Range(0, 300).Concat(new[] { 1024, 4095, 4096, 4097, 5000 }))
        {
            var span = data.AsSpan(0, length);
            var expected = System.IO.Hashing.Crc32.HashToUInt32(span);
            Assert.Equal(expected, Arc.Crypto.Crc32.Hash32(span));

            foreach (var chunk in new[] { 1, 3, 7, 8, 9, 64 })
            {
                crc.HashInitialize();
                for (var i = 0; i < length; i += chunk)
                {
                    crc.HashUpdate(span.Slice(i, Math.Min(chunk, length - i)));
                }

                Assert.Equal(expected, BitConverter.ToUInt32(crc.HashFinal()));
            }
        }
    }

    [Fact]
    public void Sha3MatchesSystemImplementation()
    {
        if (!SHA3_256.IsSupported || !SHA3_384.IsSupported || !SHA3_512.IsSupported)
        {
            return;
        }

        var random = new Xoshiro256StarStar(7);
        var data = new byte[1100];
        random.NextBytes(data);
        Sha3[] hashes = [new Sha3_256(), new Sha3_384(), new Sha3_512()];
        foreach (var length in new[] { 0, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137, 271, 272, 273, 1100 })
        {
            var span = data.AsSpan(0, length);
            byte[][] expected = [SHA3_256.HashData(span), SHA3_384.HashData(span), SHA3_512.HashData(span)];
            for (var h = 0; h < hashes.Length; h++)
            {
                Assert.Equal(expected[h], hashes[h].GetHash(span));
                foreach (var chunk in new[] { 1, 5, 8, 72, 100 })
                {
                    hashes[h].HashInitialize();
                    for (var i = 0; i < length; i += chunk)
                    {
                        hashes[h].HashUpdate(span.Slice(i, Math.Min(chunk, length - i)));
                    }

                    Assert.Equal(expected[h], hashes[h].HashFinal());
                }
            }
        }
    }

    [Fact]
    public void SeedOverlappingKeyOutputDerivesTheSameKeys()
    {
        var seed = new byte[CryptoSign.SeedSize];
        new Xoshiro256StarStar(8).NextBytes(seed);
        var expectedSecret = new byte[CryptoSign.SecretKeySize];
        var expectedPublic = new byte[CryptoSign.PublicKeySize];
        var expectedBoxSecret = new byte[CryptoBox.SecretKeySize];
        var expectedBoxPublic = new byte[CryptoBox.PublicKeySize];
        CryptoSign.CreateKeyPair(seed, expectedSecret, expectedPublic);

        // Regenerating a key pair from the seed stored in the secret key itself.
        var secret = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        seed.CopyTo(secret, 0);
        CryptoSign.CreateKeyPair(secret.AsSpan(0, CryptoSign.SeedSize), secret, publicKey);
        Assert.Equal(expectedSecret, secret);
        Assert.Equal(expectedPublic, publicKey);

        seed.CopyTo(publicKey, 0);
        CryptoSign.CreateKeyPair(publicKey, secret, publicKey);
        Assert.Equal(expectedSecret, secret);
        Assert.Equal(expectedPublic, publicKey);

        CryptoDual.CreateKeyPair(seed, expectedSecret, expectedPublic, expectedBoxSecret, expectedBoxPublic);
        var boxSecret = new byte[CryptoBox.SecretKeySize];
        var boxPublic = new byte[CryptoBox.PublicKeySize];
        seed.CopyTo(secret, 0);
        CryptoDual.CreateKeyPair(secret.AsSpan(0, CryptoSign.SeedSize), secret, publicKey, boxSecret, boxPublic);
        Assert.Equal(expectedSecret, secret);
        Assert.Equal(expectedPublic, publicKey);
        Assert.Equal(expectedBoxSecret, boxSecret);
        Assert.Equal(expectedBoxPublic, boxPublic);
    }

    [Fact]
    public void SignPublicKeyToBoxConversion()
    {
        var secret = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        var expected = new byte[CryptoBox.PublicKeySize];
        var actual = new byte[CryptoBox.PublicKeySize];
        for (var i = 0; i < 100; i++)
        {// Valid keys agree with libsodium, apart from the added sign bit.
            CryptoSign.CreateKeyPair(secret, publicKey);
            Assert.Equal(0, Arc.Crypto.LibsodiumInterops.crypto_sign_ed25519_pk_to_curve25519(expected, publicKey));
            expected[31] |= (byte)(publicKey[31] & 0x80);
            CryptoDual.ConvertSignPublicKeyToBox(publicKey, actual);
            Assert.Equal(expected, actual);
        }

        // About half of random inputs are not curve points; they used to collapse to the same key.
        var random = new Xoshiro256StarStar(9);
        var seen = new HashSet<string>();
        var roundTrip = new byte[CryptoSign.PublicKeySize];
        for (var i = 0; i < 1000; i++)
        {
            random.NextBytes(publicKey);
            CryptoDual.ConvertSignPublicKeyToBox(publicKey, actual);
            Assert.True(seen.Add(Convert.ToHexString(actual)));
            CryptoDual.ConvertBoxPublicKeyToSign(actual, roundTrip);
            Assert.Equal(publicKey, roundTrip);
        }
    }

    private static void Encrypt(int variant, Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, int tagSize)
    {
        if (variant == 128)
        {
            Aegis128L.Encrypt(ciphertext, plaintext, nonce, key, default, tagSize);
        }
        else
        {
            Aegis256.Encrypt(ciphertext, plaintext, nonce, key, default, tagSize);
        }
    }

    private static bool TryDecrypt(int variant, Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, int tagSize)
        => variant == 128 ?
        Aegis128L.TryDecrypt(plaintext, ciphertext, nonce, key, default, tagSize) :
        Aegis256.TryDecrypt(plaintext, ciphertext, nonce, key, default, tagSize);

    private static IHash CreateHash(string name) => name switch
    {
        "SHA1" => new Sha1(),
        "SHA2-256" => new Sha2_256(),
        "SHA2-384" => new Sha2_384(),
        "SHA2-512" => new Sha2_512(),
        "SHA3-256" => new Sha3_256(),
        "SHA3-384" => new Sha3_384(),
        "SHA3-512" => new Sha3_512(),
        "xxHash32" => new XxHash32(),
        "xxHash64" => new XxHash64(),
        "CRC-32" => new Arc.Crypto.Crc32(),
        _ => new Adler32(),
    };
}
