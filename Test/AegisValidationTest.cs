// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using Xunit;

namespace Test;

public class AegisValidationTest
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicValidationAndPortableAuthentication(bool small)
    {
        Action<Span<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, int> encrypt = small ? Aegis128L.Encrypt : Aegis256.Encrypt;
        Func<Span<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, int, bool> decrypt = small ? Aegis128L.TryDecrypt : Aegis256.TryDecrypt;
        Action<Span<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, int> softEncrypt = small ? Aegis128LSoft.Encrypt : Aegis256Soft.Encrypt;
        Func<Span<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, int, bool> softDecrypt = small ? Aegis128LSoft.Decrypt : Aegis256Soft.Decrypt;
        var key = new byte[small ? 16 : 32];
        var nonce = new byte[key.Length];
        var message = new byte[33];
        var ad = "associated data"u8.ToArray();
        var cipher = new byte[49];
        var nonceName = small ? "nonce16" : "nonce32";
        var keyName = small ? "key16" : "key32";
        foreach (var tag in new[] { -1, 1, 15, 17, 31, 33, })
        {// The buffers fit the tag size, so only the tagSize check can reject it.
            Assert.Throws<ArgumentOutOfRangeException>("tagSize", () => encrypt(new byte[message.Length + tag], message, nonce, key, ad, tag));
            Assert.Throws<ArgumentOutOfRangeException>("tagSize", () => decrypt(message, new byte[message.Length + tag], nonce, key, ad, tag));
        }

        foreach (var tag in new[] { int.MinValue, int.MaxValue, })
        {
            Assert.Throws<ArgumentOutOfRangeException>("tagSize", () => encrypt(cipher, message, nonce, key, ad, tag));
            Assert.Throws<ArgumentOutOfRangeException>("tagSize", () => decrypt(message, cipher, nonce, key, ad, tag));
        }

        // A rejected tag size must not write anything, in particular past the end of the ciphertext span.
        var canary = new byte[message.Length + 17 + 32];
        canary.AsSpan().Fill(0xCC);
        Assert.Throws<ArgumentOutOfRangeException>("tagSize", () => encrypt(canary.AsSpan(0, message.Length + 17), message, nonce, key, ad, 17));
        Assert.All(canary, value => Assert.Equal(0xCC, value));

        Assert.Throws<ArgumentOutOfRangeException>("ciphertext", () => encrypt(new byte[48], message, nonce, key, ad, 16));
        Assert.Throws<ArgumentOutOfRangeException>("ciphertext", () => decrypt(message, new byte[15], nonce, key, ad, 16));
        Assert.Throws<ArgumentOutOfRangeException>("plaintext", () => decrypt(new byte[32], cipher, nonce, key, ad, 16));

        // The nonce and key must have the exact size: shorter or longer inputs (such as an AEGIS-256 key passed to AEGIS-128L) are rejected, not truncated.
        foreach (var length in new[] { 0, key.Length - 1, key.Length + 1, key.Length * 2, })
        {
            Assert.Throws<ArgumentOutOfRangeException>(nonceName, () => encrypt(cipher, message, new byte[length], key, ad, 16));
            Assert.Throws<ArgumentOutOfRangeException>(keyName, () => encrypt(cipher, message, nonce, new byte[length], ad, 16));
            Assert.Throws<ArgumentOutOfRangeException>(nonceName, () => decrypt(message, cipher, new byte[length], key, ad, 16));
            Assert.Throws<ArgumentOutOfRangeException>(keyName, () => decrypt(message, cipher, nonce, new byte[length], ad, 16));
        }

        var random = new Random(42);
        random.NextBytes(key);
        random.NextBytes(nonce);
        foreach (var length in new[] { 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, })
        {
            message = new byte[length];
            random.NextBytes(message);
            foreach (var tag in new[] { 0, 16, 32, })
            {
                cipher = new byte[length + tag];
                var portable = new byte[cipher.Length];
                var output = new byte[length];
                encrypt(cipher, message, nonce, key, ad, tag);
                softEncrypt(portable, message, nonce, key, ad, tag);
                Assert.Equal(cipher, portable);
                Assert.True(softDecrypt(output, cipher, nonce, key, ad, tag));
                Assert.Equal(message, output);
                var inPlace = new byte[cipher.Length];
                message.CopyTo(inPlace, 0);
                encrypt(inPlace, inPlace.AsSpan(0, length), nonce, key, ad, tag);
                Assert.Equal(cipher, inPlace);
                Assert.True(decrypt(inPlace.AsSpan(0, length), inPlace, nonce, key, ad, tag));
                Assert.Equal(message, inPlace[..length]);
                if (tag != 0)
                {
                    cipher[^1] ^= 1;
                    output.AsSpan().Fill(0xA5);
                    Assert.False(softDecrypt(output, cipher, nonce, key, ad, tag));
                    Assert.All(output, value => Assert.Equal(0, value));
                    output.AsSpan().Fill(0xA5);
                    Assert.False(decrypt(output, cipher, nonce, key, ad, tag));
                    Assert.All(output, value => Assert.Equal(0, value));
                    cipher[^1] ^= 1;
                    ad[0] ^= 1;
                    output.AsSpan().Fill(0xA5);
                    Assert.False(decrypt(output, cipher, nonce, key, ad, tag));
                    Assert.All(output, value => Assert.Equal(0, value));
                    ad[0] ^= 1;
                }
            }
        }
    }
}
