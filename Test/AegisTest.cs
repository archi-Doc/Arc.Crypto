// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access

namespace Test;

public class AegisTest
{
    [Fact]
    public void Test256()
    {
        var random = new Xoroshiro128StarStar(12);
        Span<byte> key = stackalloc byte[Aegis256.KeySize];
        Span<byte> nonce = stackalloc byte[Aegis256.NonceSize];

        for (var j = 0; j < 1000; j += 13)
        {
            var message = new byte[j];
            var message2 = new byte[j];
            random.NextBytes(message);
            var cipher = new byte[message.Length + Aegis256.MaxTagSize];
            var cipher2 = new byte[message.Length + Aegis256.MaxTagSize];

            Aegis256.Encrypt(cipher, message, nonce, key, default, 32);
            Aegis256.TryDecrypt(message2, cipher, nonce, key, default, 32);
            message.SequenceEqual(message2).IsTrue();

            Aegis256Helper.Encrypt(message, nonce, key, cipher2, out _);
            cipher.SequenceEqual(cipher2).IsTrue();
        }
    }

    [Fact]
    public void Test128()
    {
        var random = new Xoroshiro128StarStar(12);
        Span<byte> key = stackalloc byte[Aegis128L.KeySize];
        Span<byte> nonce = stackalloc byte[Aegis128L.NonceSize];

        for (var j = 0; j < 1000; j += 13)
        {
            var message = new byte[j];
            var message2 = new byte[j];
            random.NextBytes(message);
            var cipher = new byte[message.Length + Aegis128L.MaxTagSize];
            var cipher2 = new byte[message.Length + Aegis128L.MaxTagSize];

            Aegis128L.Encrypt(cipher, message, nonce, key, default, 32);
            Aegis128L.TryDecrypt(message2, cipher, nonce, key, default, 32);
            message.SequenceEqual(message2).IsTrue();
        }
    }
}
