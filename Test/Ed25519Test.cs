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
        Span<byte> seed = stackalloc byte[Ed25519Helper.SeedSizeInBytes];
        Span<byte> seed2 = stackalloc byte[Ed25519Helper.SeedSizeInBytes];
        Span<byte> signature = stackalloc byte[Ed25519Helper.SignatureSizeInBytes];
        Span<byte> signature2 = stackalloc byte[Ed25519Helper.SignatureSizeInBytes];
        Span<byte> secretKey = stackalloc byte[Ed25519Helper.SecretKeySizeInBytes];
        Span<byte> publicKey = stackalloc byte[Ed25519Helper.PublicKeySizeInBytes];
        Span<byte> publicKey2 = stackalloc byte[Ed25519Helper.PublicKeySizeInBytes];

        for (var i = 0; i < 100; i++)
        {// Create key, secret key -> public key, secret key -> seed
            random.NextBytes(seed);
            Ed25519Helper.CreateKey(seed, secretKey, publicKey);

            Ed25519Helper.SecretKeyToPublicKey(secretKey, publicKey2);
            publicKey.SequenceEqual(publicKey2).IsTrue();
            Ed25519Helper.SecretKeyToSeed(secretKey, seed2);
            seed.SequenceEqual(seed2).IsTrue();
        }

        for (var i = 0; i < 32; i++)
        {
            random.NextBytes(seed);
            Ed25519Helper.CreateKey(seed, secretKey, publicKey);

            for (var j = 0; j < 1000; j += 13)
            {
                var message = new byte[i + j];
                random.NextBytes(message);

                Ed25519Helper.Sign(message, secretKey, signature);
                Ed25519Helper.Verify(message, publicKey, signature).IsTrue();

                var ed25519ph = Ed25519ph.New();
                var m = message.AsSpan();
                var half = message.Length / 2;
                ed25519ph.Update(m);
                // ed25519ph.Update(m.Slice(0, half));
                // ed25519ph.Update(m.Slice(half, message.Length - half));
                ed25519ph.FinalizeAndSign(secretKey, signature2);
                // signature.SequenceEqual(signature2).IsTrue();

                ed25519ph.Update(m.Slice(0, half));
                ed25519ph.Update(m.Slice(half, message.Length - half));
                ed25519ph.FinalizeAndVerify(publicKey, signature2).IsTrue();
            }
        }
    }
}
