// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto;
using Xunit;

namespace Test;

public class CryptoDualTest
{
    [Fact]
    public void SeedKeyPairMatchesSignAndBoxKeyPairs()
    {// CryptoDual used to call crypto_box_seed_keypair; the box public key is now converted from the Ed25519 key instead.
        var random = new Xoshiro256StarStar(30);
        var seed = new byte[CryptoSign.SeedSize];
        var signSecret = new byte[CryptoSign.SecretKeySize];
        var signPublic = new byte[CryptoSign.PublicKeySize];
        var boxSecret = new byte[CryptoBox.SecretKeySize];
        var boxPublic = new byte[CryptoBox.PublicKeySize];
        var dualSignSecret = new byte[CryptoSign.SecretKeySize];
        var dualSignPublic = new byte[CryptoSign.PublicKeySize];
        var dualBoxSecret = new byte[CryptoBox.SecretKeySize];
        var dualBoxPublic = new byte[CryptoBox.PublicKeySize];
        var signBits = 0;
        const int Count = 300;
        for (var i = 0; i < Count; i++)
        {
            if (i == 0)
            {
                Array.Fill(seed, (byte)0);
            }
            else if (i == 1)
            {
                Array.Fill(seed, (byte)0xFF);
            }
            else if (i == 2)
            {
                seed = Enumerable.Range(0, CryptoSign.SeedSize).Select(x => (byte)x).ToArray();
            }
            else
            {
                random.NextBytes(seed);
            }

            // Previous derivation: crypto_sign_seed_keypair and crypto_box_seed_keypair, plus the sign bit.
            CryptoSign.CreateKeyPair(seed, signSecret, signPublic);
            CryptoBox.CreateKeyPair(seed, boxSecret, boxPublic);
            (boxPublic[31] & 0x80).Is(0);
            boxPublic[31] |= (byte)(signPublic[31] & 0x80);
            signBits += signPublic[31] >> 7;

            CryptoDual.CreateKeyPair(seed, dualSignSecret, dualSignPublic, dualBoxSecret, dualBoxPublic);
            dualSignSecret.Is(signSecret);
            dualSignPublic.Is(signPublic);
            dualBoxSecret.Is(boxSecret);
            dualBoxPublic.Is(boxPublic);
        }

        (signBits > 0 && signBits < Count).IsTrue(); // Both sign bit values are exercised.
    }

    [Fact]
    public void RandomKeyPairIsConsistent()
    {
        var signSecret = new byte[CryptoSign.SecretKeySize];
        var signPublic = new byte[CryptoSign.PublicKeySize];
        var boxSecret = new byte[CryptoBox.SecretKeySize];
        var boxPublic = new byte[CryptoBox.PublicKeySize];
        CryptoDual.CreateKeyPair(signSecret, signPublic, boxSecret, boxPublic);

        var signSecret2 = new byte[CryptoSign.SecretKeySize];
        var signPublic2 = new byte[CryptoSign.PublicKeySize];
        var boxSecret2 = new byte[CryptoBox.SecretKeySize];
        var boxPublic2 = new byte[CryptoBox.PublicKeySize];
        CryptoDual.CreateKeyPair(signSecret.AsSpan(0, CryptoSign.SeedSize), signSecret2, signPublic2, boxSecret2, boxPublic2);
        signSecret2.Is(signSecret);
        signPublic2.Is(signPublic);
        boxSecret2.Is(boxSecret);
        boxPublic2.Is(boxPublic);

        var converted = new byte[CryptoBox.PublicKeySize];
        CryptoDual.ConvertSignPublicKeyToBox(signPublic, converted);
        converted.Is(boxPublic);
        (boxPublic[31] & 0x80).Is(signPublic[31] & 0x80);
        CryptoDual.ConvertSignSecretKeyToBox(signSecret, converted);
        converted.Is(boxSecret);

        CryptoDual.CreateKeyPair(signSecret2, signPublic2, boxSecret2, boxPublic2);
        signSecret2.SequenceEqual(signSecret).IsFalse();
    }

    [Fact]
    public void ConvertSignSecretKeyToBoxMatchesBoxKey()
    {
        var random = new Xoshiro256StarStar(31);
        var seed = new byte[CryptoSign.SeedSize];
        var signSecret = new byte[CryptoSign.SecretKeySize];
        var signPublic = new byte[CryptoSign.PublicKeySize];
        var boxSecret = new byte[CryptoBox.SecretKeySize];
        var boxPublic = new byte[CryptoBox.PublicKeySize];
        var converted = new byte[CryptoBox.SecretKeySize];
        var libsodium = new byte[CryptoBox.SecretKeySize];
        var basePoint = new byte[CryptoBox.PublicKeySize];
        basePoint[0] = 9;
        var derived = new byte[CryptoBox.PublicKeySize];
        for (var i = 0; i < 32; i++)
        {
            random.NextBytes(seed);
            CryptoDual.CreateKeyPair(seed, signSecret, signPublic, boxSecret, boxPublic);
            CryptoDual.ConvertSignSecretKeyToBox(signSecret, converted);
            converted.Is(boxSecret);
            converted.Is(SHA512.HashData(seed).AsSpan(0, CryptoBox.SecretKeySize).ToArray());

            // libsodium returns the clamped scalar; X25519 clamps on use, so both are the same key.
            Arc.Crypto.LibsodiumInterops.crypto_sign_ed25519_sk_to_curve25519(libsodium, signSecret).Is(0);
            var clamped = converted.ToArray();
            clamped[0] &= 248;
            clamped[31] &= 127;
            clamped[31] |= 64;
            clamped.Is(libsodium);

            CryptoBox.DeriveSharedSecret(converted, basePoint, derived);
            CryptoDual.BoxPublicKeyEquals(derived, boxPublic).IsTrue();

            var buffer = signSecret.ToArray();
            CryptoDual.ConvertSignSecretKeyToBox(buffer, buffer.AsSpan(0, CryptoBox.SecretKeySize));
            buffer.AsSpan(0, CryptoBox.SecretKeySize).ToArray().Is(boxSecret);
        }
    }

    [Fact]
    public void BoxPublicKeyEqualsIgnoresOnlyTheSignBit()
    {
        var key = new byte[CryptoBox.PublicKeySize];
        new Random(3).NextBytes(key);
        CryptoDual.BoxPublicKeyEquals(key, key.ToArray()).IsTrue();
        CryptoDual.BoxPublicKeyEquals(key, Flip(key, 31, 0x80)).IsTrue();
        CryptoDual.BoxPublicKeyEquals(key, Flip(key, 31, 0x01)).IsFalse();
        CryptoDual.BoxPublicKeyEquals(key, Flip(key, 31, 0x40)).IsFalse();
        CryptoDual.BoxPublicKeyEquals(key, Flip(key, 0, 0x01)).IsFalse();
        CryptoDual.BoxPublicKeyEquals(key, Flip(key, 30, 0x80)).IsFalse();
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.BoxPublicKeyEquals(new byte[31], key));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.BoxPublicKeyEquals(key, new byte[33]));

        static byte[] Flip(byte[] source, int index, byte mask)
        {
            var copy = source.ToArray();
            copy[index] ^= mask;
            return copy;
        }
    }

    [Fact]
    public void InvalidSizesThrow()
    {
        var b31 = new byte[31];
        var b32 = new byte[32];
        var b33 = new byte[33];
        var b63 = new byte[63];
        var b64 = new byte[64];
        var b65 = new byte[65];

        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b63, b32, b32, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b64, b31, b32, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b64, b32, b33, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b64, b32, b32, b31));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b31, b64, b32, b32, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b33, b64, b32, b32, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b32, b65, b32, b32, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b32, b64, b33, b32, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b32, b64, b32, b31, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.CreateKeyPair(b32, b64, b32, b32, b33));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.ConvertSignSecretKeyToBox(b63, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.ConvertSignSecretKeyToBox(b65, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.ConvertSignSecretKeyToBox(b64, b31));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.ConvertSignSecretKeyToBox(b64, b33));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.ConvertSignPublicKeyToBox(b31, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.ConvertSignPublicKeyToBox(b32, b33));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.ConvertBoxPublicKeyToSign(b33, b32));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoDual.ConvertBoxPublicKeyToSign(b32, b31));
    }
}
