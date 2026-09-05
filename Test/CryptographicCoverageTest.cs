// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Arc.Crypto;
using Xunit;

namespace Test;

public class CryptographicCoverageTest
{
    [Fact]
    public void DualPublicKeyConversionPreservesSignInPlace()
    {
        var seed = new byte[32];
        var secret = new byte[64];
        var publicKey = new byte[32];
        var box = new byte[32];
        var random = new Random(42);
        var seenSignBits = 0;
        for (var i = 0; i < 100; i++)
        {
            random.NextBytes(seed);
            CryptoSign.CreateKey(seed, secret, publicKey);
            seenSignBits |= 1 << (publicKey[31] >> 7);
            CryptoDual.PublicKey_SignToBox(publicKey, box);
            var inPlace = publicKey.ToArray();
            CryptoDual.PublicKey_SignToBox(inPlace, inPlace);
            Assert.Equal(box, inPlace);
            CryptoDual.PublicKey_BoxToSign(inPlace, inPlace);
            Assert.Equal(publicKey, inPlace);
        }

        Assert.Equal(3, seenSignBits);
    }

    [Theory]
    [InlineData("", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")]
    [InlineData("abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")]
    public void Blake2KnownAnswers(string text, string hash256, string hash512)
    {
        var input = System.Text.Encoding.UTF8.GetBytes(text);
        var expected256 = Convert.FromHexString(hash256);
        var expected512 = Convert.FromHexString(hash512);
        Assert.Equal(expected256, Blake2B.Get256_ByteArray(input));
        Assert.Equal(expected512, Blake2B.Get512_ByteArray(input));
        Assert.Equal(expected256, TupleBytes(Blake2B.Get256_UInt64(input)));
        var value = Blake2B.Get256_Struct(input);
        Assert.Equal(expected256, MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref value, 1)).ToArray());
        var output = new byte[64];
        Blake2B.Get256_Span(input, output.AsSpan(0, 32));
        Assert.Equal(expected256, output[..32]);
        Blake2B.Get512_Span(input, output);
        Assert.Equal(expected512, output);
        Assert.Throws<ArgumentException>(() => Blake2B.Get256_Span(input, new byte[31]));
        Assert.Throws<ArgumentException>(() => Blake2B.Get256_Span(input, new byte[33]));
        Assert.Throws<ArgumentException>(() => Blake2B.Get512_Span(input, new byte[63]));
        Assert.Throws<ArgumentException>(() => Blake2B.Get512_Span(input, new byte[65]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(71)]
    [InlineData(72)]
    [InlineData(103)]
    [InlineData(104)]
    [InlineData(135)]
    [InlineData(136)]
    [InlineData(137)]
    [InlineData(1025)]
    public void ShaHelperOverloadsAgree(int length)
    {
        var input = new byte[length];
        new Random(42).NextBytes(input);
        Assert.Equal(SHA256.HashData(input), Sha2Helper.Get256_ByteArray(input));
        Assert.Equal(SHA384.HashData(input), Sha2Helper.Get384_ByteArray(input));
        Assert.Equal(SHA512.HashData(input), Sha2Helper.Get512_ByteArray(input));
        Assert.Equal(SHA256.HashData(input), TupleBytes(Sha2Helper.Get256_UInt64(input)));
        Assert.Equal(SHA384.HashData(input), TupleBytes(Sha2Helper.Get384_UInt64(input)));
        Assert.Equal(SHA512.HashData(input), TupleBytes(Sha2Helper.Get512_UInt64(input)));

        Assert.Equal(Sha3Helper.Get256_ByteArray(input), TupleBytes(Sha3Helper.Get256_UInt64(input)));
        Assert.Equal(Sha3Helper.Get384_ByteArray(input), TupleBytes(Sha3Helper.Get384_UInt64(input)));
        Assert.Equal(Sha3Helper.Get512_ByteArray(input), TupleBytes(Sha3Helper.Get512_UInt64(input)));
        if (SHA3_256.IsSupported)
        {
            Assert.Equal(SHA3_256.HashData(input), Sha3Helper.Get256_ByteArray(input));
            Assert.Equal(SHA3_384.HashData(input), Sha3Helper.Get384_ByteArray(input));
            Assert.Equal(SHA3_512.HashData(input), Sha3Helper.Get512_ByteArray(input));
        }

        VerifyOutput(Sha2Helper.Get256_Span, input, SHA256.HashData(input));
        VerifyOutput(Sha2Helper.Get384_Span, input, SHA384.HashData(input));
        VerifyOutput(Sha2Helper.Get512_Span, input, SHA512.HashData(input));
        VerifyOutput(Sha2Helper.Get512_Libsodium, input, SHA512.HashData(input));
        VerifyOutput(Sha3Helper.Get256_Span, input, Sha3Helper.Get256_ByteArray(input));
        VerifyOutput(Sha3Helper.Get384_Span, input, Sha3Helper.Get384_ByteArray(input));
        VerifyOutput(Sha3Helper.Get512_Span, input, Sha3Helper.Get512_ByteArray(input));

        foreach (var hash in new Sha3[] { new Sha3_256(), new Sha3_384(), new Sha3_512(), })
        {
            var expected = hash.GetHash(input);
            for (var split = 0; split <= Math.Min(length, 140); split++)
            {
                hash.HashInitialize();
                hash.HashUpdate(input.AsSpan(0, split));
                hash.HashUpdate(input, split, length - split);
                Assert.Equal(expected, hash.HashFinal());
            }

            VerifyOutput(hash.GetHash, input, expected);
            Assert.True(hash.IsCryptographic);
            Assert.Equal(hash.HashBits / 8, hash.HashBytes);
            Assert.StartsWith("SHA3-", hash.HashName);
        }
    }

    [Theory]
    [InlineData(256, 136)]
    [InlineData(384, 104)]
    [InlineData(512, 72)]
    public void Sha3ResetAtBlockBoundaryAndRetryFinalization(int bits, int blockSize)
    {
        Sha3 hash = bits switch { 256 => new Sha3_256(), 384 => new Sha3_384(), _ => new Sha3_512(), };
        var expected = hash.GetHash("abc"u8);
        hash.HashUpdate(new byte[blockSize]);
        hash.HashInitialize();
        hash.HashUpdate("abc"u8);
        Assert.Throws<ArgumentException>(() => hash.HashFinal(new byte[(bits / 8) - 1]));
        Assert.Equal(expected, hash.HashFinal());
        Assert.Equal(expected, hash.GetHash("abc"u8));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(31)]
    [InlineData(1025)]
    public void SecretBoxRoundTripAndTampering(int length)
    {
        var message = new byte[length];
        new Random(42).NextBytes(message);
        var key = new byte[CryptoSecretBox.KeySize];
        var nonce = new byte[CryptoSecretBox.NonceSize];
        CryptoSecretBox.CreateKey(key);
        CryptoRandom.NextBytes(nonce);
        var cipher = new byte[length + CryptoSecretBox.MacSize];
        var output = new byte[length];
        CryptoSecretBox.Encrypt(message, nonce, key, cipher);
        Assert.True(CryptoSecretBox.TryDecrypt(cipher, nonce, key, output));
        Assert.Equal(message, output);
        cipher[0] ^= 1;
        Assert.False(CryptoSecretBox.TryDecrypt(cipher, nonce, key, output));
        cipher[0] ^= 1;
        key[0] ^= 1;
        Assert.False(CryptoSecretBox.TryDecrypt(cipher, nonce, key, output));
    }

    [Fact]
    public void SecretBoxValidatesEveryBuffer()
    {
        var key = new byte[32];
        var nonce = new byte[24];
        var cipher = new byte[17];
        var message = new byte[1];
        foreach (var length in new[] { 0, 31, 33, })
        {
            var wrongKey = new byte[length];
            Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSecretBox.CreateKey(wrongKey));
            Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSecretBox.Encrypt(message, nonce, wrongKey, cipher));
            Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSecretBox.TryDecrypt(cipher, nonce, wrongKey, message));
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSecretBox.Encrypt(message, new byte[23], key, cipher));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSecretBox.Encrypt(message, nonce, key, new byte[16]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSecretBox.TryDecrypt(new byte[15], nonce, key, message));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSecretBox.TryDecrypt(cipher, new byte[25], key, message));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSecretBox.TryDecrypt(cipher, nonce, key, new byte[2]));
    }

    [Fact]
    public void BoxKeyAgreementAndInvalidPublicKeys()
    {
        var aliceSecret = new byte[32];
        var alicePublic = new byte[32];
        var bobSecret = new byte[32];
        var bobPublic = new byte[32];
        CryptoBox.CreateKey(aliceSecret, alicePublic);
        CryptoBox.CreateKey(bobSecret, bobPublic);
        var aliceMaterial = new byte[32];
        var bobMaterial = new byte[32];
        CryptoBox.DeriveKeyMaterial(aliceSecret, bobPublic, aliceMaterial);
        CryptoBox.DeriveKeyMaterial(bobSecret, alicePublic, bobMaterial);
        Assert.Equal(aliceMaterial, bobMaterial);
        var nonce = new byte[24];
        var cipher = new byte[19];
        var message = new byte[3];
        CryptoBox.Encrypt("abc"u8, nonce, aliceSecret, bobPublic, cipher);
        Assert.True(CryptoBox.TryDecrypt(cipher, nonce, bobSecret, alicePublic, message));
        Assert.Equal("abc"u8.ToArray(), message);
        cipher[0] ^= 1;
        Assert.False(CryptoBox.TryDecrypt(cipher, nonce, bobSecret, alicePublic, message));
        foreach (var lowOrder in new byte[] { 0, 1, })
        {
            var invalidKey = new byte[32];
            invalidKey[0] = lowOrder;
            aliceMaterial.AsSpan().Fill(0xA5);
            Assert.Throws<CryptographicException>(() => CryptoBox.DeriveKeyMaterial(aliceSecret, invalidKey, aliceMaterial));
            Assert.All(aliceMaterial, x => Assert.Equal(0, x));
            Assert.Throws<CryptographicException>(() => CryptoBox.Encrypt("abc"u8, nonce, aliceSecret, invalidKey, cipher));
            Assert.All(cipher, x => Assert.Equal(0, x));
        }
    }

    [Fact]
    public void BoxValidatesEveryBuffer()
    {
        var key = new byte[32];
        var wrongKey = new byte[31];
        var nonce = new byte[24];
        var cipher = new byte[17];
        var message = new byte[1];
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.CreateKey(wrongKey, key));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.CreateKey(key, wrongKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.CreateKey(wrongKey, key, key));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.CreateKey(key, wrongKey, key));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.CreateKey(key, key, wrongKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.Encrypt(message, new byte[23], key, key, cipher));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.Encrypt(message, nonce, wrongKey, key, cipher));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.Encrypt(message, nonce, key, wrongKey, cipher));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.Encrypt(message, nonce, key, key, new byte[16]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.TryDecrypt(new byte[15], nonce, key, key, message));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.TryDecrypt(cipher, new byte[25], key, key, message));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.TryDecrypt(cipher, nonce, wrongKey, key, message));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.TryDecrypt(cipher, nonce, key, wrongKey, message));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.TryDecrypt(cipher, nonce, key, key, new byte[2]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.DeriveKeyMaterial(wrongKey, key, key));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.DeriveKeyMaterial(key, wrongKey, key));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBox.DeriveKeyMaterial(key, key, wrongKey));
    }

    private static byte[] TupleBytes(ITuple tuple)
    {
        var words = new ulong[tuple.Length];
        for (var i = 0; i < words.Length; i++)
        {
            words[i] = (ulong)tuple[i]!;
        }

        return MemoryMarshal.AsBytes(words.AsSpan()).ToArray();
    }

    private static void VerifyOutput(Action<ReadOnlySpan<byte>, Span<byte>> hash, byte[] input, byte[] expected)
    {
        var output = Enumerable.Repeat((byte)0xA5, expected.Length + 17).ToArray();
        hash(input, output);
        Assert.Equal(expected, output[..expected.Length]);
        Assert.All(output[expected.Length..], x => Assert.Equal(0xA5, x));
    }
}
