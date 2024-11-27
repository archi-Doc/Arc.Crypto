// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        Span<byte> seed = stackalloc byte[CryptoSign.SeedSize];
        Span<byte> seed2 = stackalloc byte[CryptoSign.SeedSize];
        Span<byte> signature = stackalloc byte[CryptoSign.SignatureSize];
        Span<byte> signature2 = stackalloc byte[CryptoSign.SignatureSize];
        Span<byte> secretKey = stackalloc byte[CryptoSign.SecretKeySize];
        Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeySize];
        Span<byte> publicKey2 = stackalloc byte[CryptoSign.PublicKeySize];

        for (var i = 0; i < 100; i++)
        {// Create key, secret key -> public key, secret key -> seed
            random.NextBytes(seed);
            CryptoSign.CreateKey(seed, secretKey, publicKey);

            CryptoSign.SecretKeyToPublicKey(secretKey, publicKey2);
            publicKey.SequenceEqual(publicKey2).IsTrue();
            CryptoSign.SecretKeyToSeed(secretKey, seed2);
            seed.SequenceEqual(seed2).IsTrue();
            secretKey.Slice(0, CryptoSign.SeedSize).SequenceEqual(seed).IsTrue(); // Secret key = Seed + Public key
        }

        for (var i = 0; i < 32; i++)
        {
            random.NextBytes(seed);
            CryptoSign.CreateKey(seed, secretKey, publicKey);

            for (var j = 0; j < 1000; j += 13)
            {
                var message = new byte[i + j];
                random.NextBytes(message);

                CryptoSign.Sign(message, secretKey, signature);
                CryptoSign.Verify(message, publicKey, signature).IsTrue();

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

    [Fact]
    public void Test2()
    {
        var random = new Xoroshiro128StarStar(12);
        Span<byte> seed = stackalloc byte[CryptoSign.SeedSize];
        random.NextBytes(seed);
        Span<byte> signSecretKey = stackalloc byte[CryptoSign.SecretKeySize];
        Span<byte> signPublicKey = stackalloc byte[CryptoSign.PublicKeySize];
        Span<byte> boxSecretKey = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> boxPublicKey = stackalloc byte[CryptoBox.PublicKeySize];
        Span<byte> boxSecretKey2 = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> boxPublicKey2 = stackalloc byte[CryptoBox.PublicKeySize];

        CryptoSign.CreateKey(seed, signSecretKey, signPublicKey);
        CryptoBox.CreateKey(seed, boxSecretKey, boxPublicKey);

        CryptoSign.SecretKey_SignToBox(signSecretKey, boxSecretKey2);
        boxSecretKey.SequenceEqual(boxSecretKey2).IsTrue();
        CryptoSign.PublicKey_SignToBox(signPublicKey, boxPublicKey2);
        boxPublicKey.SequenceEqual(boxPublicKey2).IsTrue();
    }

    [Fact]
    public void KeyConversionTest()
    {
        var random = new Xoroshiro128StarStar(102);
        Span<byte> seed = stackalloc byte[CryptoSign.SeedSize];
        Span<byte> signSecretKey = stackalloc byte[CryptoSign.SecretKeySize];
        Span<byte> signPublicKey = stackalloc byte[CryptoSign.PublicKeySize];
        Span<byte> boxSecretKey = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> boxPublicKey = stackalloc byte[CryptoBox.PublicKeySize];
        Span<byte> boxSecretKey2 = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> boxPublicKey2 = stackalloc byte[CryptoBox.PublicKeySize];
        Span<byte> signPublicKey3 = stackalloc byte[CryptoSign.PublicKeySize];

        for (var i = 0; i < 1_000; i++)
        {
            random.NextBytes(seed);

            CryptoSign.CreateKey(seed, signSecretKey, signPublicKey);
            CryptoBox.CreateKey(seed, boxSecretKey, boxPublicKey);

            CryptoSign.SecretKey_SignToBox(signSecretKey, boxSecretKey2);
            boxSecretKey.SequenceEqual(boxSecretKey2).IsTrue();
            CryptoSign.PublicKey_SignToBox(signPublicKey, boxPublicKey2).IsTrue();
            boxPublicKey.SequenceEqual(boxPublicKey2).IsTrue();

            CryptoSign.PublicKey_SignToBox(boxPublicKey2, signPublicKey3); // .IsTrue();
        }
    }
}
