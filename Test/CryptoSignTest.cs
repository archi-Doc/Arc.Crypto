// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using Arc.Crypto;
using Xunit;

namespace Test;

public class CryptoSignTest
{
    private const int MessageLength = 200;

    // RFC 8032, section 7.1 (Test Vectors for Ed25519), TEST 1-3: secret key (seed), public key, message, signature.
    public static TheoryData<string, string, string, string> Rfc8032Vectors => new()
    {
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            string.Empty,
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        },
        {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        },
        {
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        },
    };

    [Theory]
    [MemberData(nameof(Rfc8032Vectors))]
    public void Rfc8032KnownAnswers(string seedHex, string publicKeyHex, string messageHex, string signatureHex)
    {
        var seed = Convert.FromHexString(seedHex);
        var expectedPublicKey = Convert.FromHexString(publicKeyHex);
        var message = Convert.FromHexString(messageHex);
        var expectedSignature = Convert.FromHexString(signatureHex);

        var secretKey = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKeyPair(seed, secretKey, publicKey);
        publicKey.Is(expectedPublicKey);
        secretKey.Is(seed.Concat(expectedPublicKey).ToArray()); // Secret key = Seed + Public key

        var signature = new byte[CryptoSign.SignatureSize];
        CryptoSign.Sign(message, secretKey, signature);
        signature.Is(expectedSignature);
        CryptoSign.Verify(message, publicKey, signature).IsTrue();

        // The signature binds the message and the public key.
        CryptoSign.Verify(message.Concat(new byte[] { 0 }).ToArray(), publicKey, signature).IsFalse();
        if (message.Length > 0)
        {
            var modified = message.ToArray();
            modified[0] ^= 1;
            CryptoSign.Verify(modified, publicKey, signature).IsFalse();
            CryptoSign.Verify(ReadOnlySpan<byte>.Empty, publicKey, signature).IsFalse();
        }

        var otherPublicKey = new byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKeyPair(new byte[CryptoSign.SecretKeySize], otherPublicKey);
        CryptoSign.Verify(message, otherPublicKey, signature).IsFalse();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(100)]
    [InlineData(MessageLength - CryptoSign.SignatureSize)]
    public void SignatureOverlappingMessageIsValid(int offset)
    {// Libsodium hashes the message again after writing part of the signature; an overlapping signature used to be invalid (and leaked the key).
        var random = new Xoshiro256StarStar(10);
        var seed = new byte[CryptoSign.SeedSize];
        random.NextBytes(seed);
        var secretKey = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKeyPair(seed, secretKey, publicKey);

        var message = new byte[MessageLength];
        random.NextBytes(message);
        var expected = new byte[CryptoSign.SignatureSize];
        CryptoSign.Sign(message, secretKey, expected);

        var buffer = message.ToArray();
        CryptoSign.Sign(buffer, secretKey, buffer.AsSpan(offset, CryptoSign.SignatureSize));
        buffer.AsSpan(offset, CryptoSign.SignatureSize).ToArray().Is(expected);
        CryptoSign.Verify(message, publicKey, expected).IsTrue();
    }

    [Fact]
    public void SignaturePartiallyOverlappingMessageIsValid()
    {
        var random = new Xoshiro256StarStar(11);
        var secretKey = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKeyPair(secretKey, publicKey);

        // Message buffer[64..200], signature buffer[32..96].
        var buffer = new byte[MessageLength];
        random.NextBytes(buffer);
        var message = buffer.AsSpan(64).ToArray();
        var expected = new byte[CryptoSign.SignatureSize];
        CryptoSign.Sign(message, secretKey, expected);

        CryptoSign.Sign(buffer.AsSpan(64), secretKey, buffer.AsSpan(32, CryptoSign.SignatureSize));
        buffer.AsSpan(32, CryptoSign.SignatureSize).ToArray().Is(expected);
        CryptoSign.Verify(message, publicKey, expected).IsTrue();
    }

    [Fact]
    public void InvalidSizesThrowAndLargerDestinationsAreAllowed()
    {
        var seed = new byte[CryptoSign.SeedSize];
        var secretKey = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        var signature = new byte[CryptoSign.SignatureSize];
        var message = new byte[10];
        CryptoSign.CreateKeyPair(seed, secretKey, publicKey);

        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.CreateKeyPair(new byte[63], publicKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.CreateKeyPair(secretKey, new byte[31]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.CreateKeyPair(new byte[31], secretKey, publicKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.CreateKeyPair(new byte[33], secretKey, publicKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.CreateKeyPair(seed, new byte[65], publicKey));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.CreateKeyPair(seed, secretKey, new byte[33]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.SecretKeyToSeed(new byte[63], new byte[32]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.SecretKeyToSeed(secretKey, new byte[31]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.SecretKeyToPublicKey(new byte[65], new byte[32]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.SecretKeyToPublicKey(secretKey, new byte[31]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.Sign(message, new byte[63], signature));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.Sign(message, secretKey, new byte[63]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.Verify(message, new byte[31], signature));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSign.Verify(message, publicKey, new byte[65]));

        // SecretKeyToSeed/SecretKeyToPublicKey accept larger destinations and leave the trailing bytes unchanged.
        var large = Enumerable.Repeat((byte)0xA5, 33).ToArray();
        CryptoSign.SecretKeyToSeed(secretKey, large);
        large.AsSpan(0, 32).ToArray().Is(secretKey.AsSpan(0, 32).ToArray());
        large[32].Is((byte)0xA5);

        large = Enumerable.Repeat((byte)0xA5, 33).ToArray();
        CryptoSign.SecretKeyToPublicKey(secretKey, large);
        large.AsSpan(0, 32).ToArray().Is(publicKey);
        large[32].Is((byte)0xA5);
    }
}
