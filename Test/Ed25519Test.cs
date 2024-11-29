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
    public void CryptoBoxTest()
    {
        var random = new Xoroshiro128StarStar(12);
        Span<byte> seed = stackalloc byte[CryptoBox.SeedSize];
        Span<byte> nonce = stackalloc byte[CryptoBox.NonceSize];
        Span<byte> boxSecretKey = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> boxPublicKey = stackalloc byte[CryptoBox.PublicKeySize];
        Span<byte> boxSecretKey2 = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> boxPublicKey2 = stackalloc byte[CryptoBox.PublicKeySize];
        Span<byte> message = [0, 1, 2, 4,];
        Span<byte> cipher = stackalloc byte[4 + CryptoBox.MacSize];
        bool result;

        random.NextBytes(seed);
        CryptoBox.CreateKey(seed, boxSecretKey, boxPublicKey);
        CryptoBox.CreateKey(seed, boxSecretKey2, boxPublicKey2);

        CryptoBox.Encrypt(message, nonce, boxSecretKey, boxPublicKey2, cipher);
        result = CryptoBox.TryDecrypt(cipher, nonce, boxSecretKey, boxPublicKey2, message);
        boxSecretKey2[1]++;
        result = CryptoBox.TryDecrypt(cipher, nonce, boxSecretKey2, boxPublicKey2, message);
    }

    [Fact]
    public void CryptoDualTest()
    {
        const int MessageSize = 100;

        var random = new Xoroshiro128StarStar(12);
        Span<byte> seed = stackalloc byte[CryptoBox.SeedSize];
        Span<byte> signSecretKey = stackalloc byte[CryptoSign.SecretKeySize];
        Span<byte> signPublicKey = stackalloc byte[CryptoSign.PublicKeySize];
        Span<byte> boxSecretKey = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> boxPublicKey = stackalloc byte[CryptoBox.PublicKeySize];
        Span<byte> dualSignSecretKey = stackalloc byte[CryptoSign.SecretKeySize];
        Span<byte> dualSignPublicKey = stackalloc byte[CryptoSign.PublicKeySize];
        Span<byte> dualBoxSecretKey = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> dualBoxPublicKey = stackalloc byte[CryptoBox.PublicKeySize];
        Span<byte> message = stackalloc byte[MessageSize];
        Span<byte> cipher = stackalloc byte[MessageSize + CryptoBox.MacSize];
        Span<byte> nonce = stackalloc byte[CryptoBox.NonceSize];
        Span<byte> decrypted = stackalloc byte[MessageSize];
        Span<byte> signature = stackalloc byte[CryptoSign.SignatureSize];

        Span<byte> boxSecretKey2 = stackalloc byte[CryptoBox.SecretKeySize];
        Span<byte> boxPublicKey2 = stackalloc byte[CryptoBox.PublicKeySize];
        random.NextBytes(seed);
        CryptoBox.CreateKey(seed, boxSecretKey2, boxPublicKey2);

        for (var i = 0; i < 1_000; i++)
        {
            random.NextBytes(seed);

            CryptoSign.CreateKey(seed, signSecretKey, signPublicKey);
            CryptoBox.CreateKey(seed, boxSecretKey, boxPublicKey);
            CryptoDual.CreateKey(seed, dualSignSecretKey, dualSignPublicKey, dualBoxSecretKey, dualBoxPublicKey);

            dualSignSecretKey.SequenceEqual(signSecretKey).IsTrue();
            dualSignPublicKey.SequenceEqual(signPublicKey).IsTrue();
            dualBoxSecretKey.SequenceEqual(boxSecretKey).IsTrue();
            CryptoDual.BoxPublicKey_Equals(dualBoxPublicKey, boxPublicKey).IsTrue();

            CryptoDual.PublicKey_SignToBox(dualSignPublicKey, dualBoxPublicKey);
            CryptoDual.BoxPublicKey_Equals(dualBoxPublicKey, boxPublicKey).IsTrue();
            CryptoDual.PublicKey_BoxToSign(dualBoxPublicKey, dualSignPublicKey);
            dualSignPublicKey.SequenceEqual(signPublicKey).IsTrue();

            // Encryption
            random.NextBytes(message);
            random.NextBytes(nonce);
            CryptoBox.Encrypt(message, nonce, boxSecretKey2, dualBoxPublicKey, cipher);
            CryptoBox.TryDecrypt(cipher, nonce, boxSecretKey2, dualBoxPublicKey, decrypted).IsTrue();
            message.SequenceEqual(decrypted).IsTrue();
            CryptoBox.TryDecrypt(cipher, nonce, dualBoxSecretKey, boxPublicKey2, decrypted).IsTrue();
            message.SequenceEqual(decrypted).IsTrue();

            nonce[2]++;
            CryptoBox.TryDecrypt(cipher, nonce, dualBoxSecretKey, boxPublicKey2, decrypted).IsFalse();

            // Signature
            CryptoSign.Sign(message, signSecretKey, signature);
            CryptoSign.Verify(message, signPublicKey, signature).IsTrue();
            signature[0]++;
            CryptoSign.Verify(message, signPublicKey, signature).IsFalse();
        }
    }
}
