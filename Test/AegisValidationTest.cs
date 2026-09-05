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
        foreach (var tag in new[] { -1, 1, 15, 17, 31, 33, })
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => encrypt(cipher, message, nonce, key, ad, tag));
            Assert.Throws<ArgumentOutOfRangeException>(() => decrypt(message, cipher, nonce, key, ad, tag));
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => encrypt(new byte[48], message, nonce, key, ad, 16));
        Assert.Throws<ArgumentOutOfRangeException>(() => encrypt(cipher, message, nonce[..^1], key, ad, 16));
        Assert.Throws<ArgumentOutOfRangeException>(() => encrypt(cipher, message, nonce, key[..^1], ad, 16));
        Assert.Throws<ArgumentOutOfRangeException>(() => decrypt(message, new byte[15], nonce, key, ad, 16));
        Assert.Throws<ArgumentOutOfRangeException>(() => decrypt(new byte[32], cipher, nonce, key, ad, 16));
        Assert.Throws<ArgumentOutOfRangeException>(() => decrypt(message, cipher, nonce[..^1], key, ad, 16));
        Assert.Throws<ArgumentOutOfRangeException>(() => decrypt(message, cipher, nonce, key[..^1], ad, 16));

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
                    cipher[^1] ^= 1;
                    ad[0] ^= 1;
                    Assert.False(decrypt(output, cipher, nonce, key, ad, tag));
                    Assert.All(output, value => Assert.Equal(0, value));
                    ad[0] ^= 1;
                }
            }
        }
    }
}
