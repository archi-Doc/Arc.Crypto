// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access

namespace Test;

public class Ed25519Test
{
    [Fact]
    public void Test1()
    {
        var random = new Xoroshiro128StarStar(12);
        Span<byte> seed = stackalloc byte[CryptoSignHelper.SeedSizeInBytes];
        Span<byte> seed2 = stackalloc byte[CryptoSignHelper.SeedSizeInBytes];
        Span<byte> signature = stackalloc byte[CryptoSignHelper.SignatureSizeInBytes];
        Span<byte> signature2 = stackalloc byte[CryptoSignHelper.SignatureSizeInBytes];
        Span<byte> secretKey = stackalloc byte[CryptoSignHelper.SecretKeySizeInBytes];
        Span<byte> publicKey = stackalloc byte[CryptoSignHelper.PublicKeySizeInBytes];
        Span<byte> publicKey2 = stackalloc byte[CryptoSignHelper.PublicKeySizeInBytes];

        for (var i = 0; i < 100; i++)
        {// Create key, secret key -> public key, secret key -> seed
            random.NextBytes(seed);
            CryptoSignHelper.CreateKey(seed, secretKey, publicKey);

            CryptoSignHelper.SecretKeyToPublicKey(secretKey, publicKey2);
            publicKey.SequenceEqual(publicKey2).IsTrue();
            CryptoSignHelper.SecretKeyToSeed(secretKey, seed2);
            seed.SequenceEqual(seed2).IsTrue();
            secretKey.Slice(0, CryptoSignHelper.SeedSizeInBytes).SequenceEqual(seed).IsTrue(); // Secret key = Seed + Public key
        }

        for (var i = 0; i < 32; i++)
        {
            random.NextBytes(seed);
            CryptoSignHelper.CreateKey(seed, secretKey, publicKey);

            for (var j = 0; j < 1000; j += 13)
            {
                var message = new byte[i + j];
                random.NextBytes(message);

                CryptoSignHelper.Sign(message, secretKey, signature);
                CryptoSignHelper.Verify(message, publicKey, signature).IsTrue();

                var ed25519ph = Ed25519ph.New();
                var m = message.AsSpan();
                var half = message.Length / 2;
                ed25519ph.Update(m);
                ed25519ph.FinalizeAndSign(secretKey, signature2); // signature.SequenceEqual(signature2).IsTrue();

                ed25519ph.Update(m.Slice(0, half));
                ed25519ph.Update(m.Slice(half, message.Length - half));
                ed25519ph.FinalizeAndVerify(publicKey, signature2).IsTrue();
            }
        }
    }
}
