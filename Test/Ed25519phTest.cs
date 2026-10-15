// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Ed25519phTest
{
    // RFC 8032, section 7.3 (Test Vectors for Ed25519ph), TEST abc.
    private static readonly byte[] Seed = Convert.FromHexString("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    private static readonly byte[] PublicKey = Convert.FromHexString("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    private static readonly byte[] Signature = Convert.FromHexString("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406");

    [Fact]
    public void Rfc8032KnownAnswerAndReset()
    {
        var secretKey = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKeyPair(Seed, secretKey, publicKey);
        publicKey.Is(PublicKey);

        var signature = new byte[CryptoSign.SignatureSize];
        var ph = Ed25519ph.New();
        ph.Update("ab"u8);
        ph.Update("c"u8);
        ph.FinalizeAndSign(secretKey, signature);
        signature.Is(Signature);

        // The state is reset after signing and after each verification, including a failed one.
        ph.Update("abc"u8);
        ph.FinalizeAndVerify(publicKey, signature).IsTrue();
        ph.Update("abd"u8);
        ph.FinalizeAndVerify(publicKey, signature).IsFalse();
        ph.Update("a"u8);
        ph.Update(ReadOnlySpan<byte>.Empty);
        ph.Update("bc"u8);
        ph.FinalizeAndVerify(publicKey, signature).IsTrue();

        ph.Update("abc"u8);
        ph.FinalizeAndSign(secretKey, signature);
        signature.Is(Signature);

        // A prehashed signature is not a pure Ed25519 signature of the same message.
        CryptoSign.Verify("abc"u8, publicKey, signature).IsFalse();
    }

    [Fact]
    public void DefaultInstanceBehavesLikeNew()
    {
        var secretKey = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKeyPair(Seed, secretKey, publicKey);

        // A default instance used to sign with an all-zero hash state and produce invalid signatures.
        var signature = new byte[CryptoSign.SignatureSize];
        Ed25519ph ph = default;
        ph.Update("abc"u8);
        ph.FinalizeAndSign(secretKey, signature);
        signature.Is(Signature);

        var fresh = Ed25519ph.New();
        fresh.Update("abc"u8);
        fresh.FinalizeAndVerify(publicKey, signature).IsTrue();

        Ed25519ph verifier = default;
        verifier.Update("abc"u8);
        verifier.FinalizeAndVerify(publicKey, signature).IsTrue();

        // Empty message, finalized without any Update.
        ph = default;
        ph.FinalizeAndSign(secretKey, signature);
        var expected = new byte[CryptoSign.SignatureSize];
        fresh.FinalizeAndSign(secretKey, expected);
        signature.Is(expected);

        verifier = default;
        verifier.FinalizeAndVerify(publicKey, expected).IsTrue();

        // The native state (crypto_sign_ed25519ph_state) is 208 bytes; the managed flag follows it.
        (Unsafe.SizeOf<Ed25519ph>() > 208).IsTrue();
    }

    [Fact]
    public void InvalidSizesThrowAndLeaveTheStateUnchanged()
    {
        var secretKey = new byte[CryptoSign.SecretKeySize];
        var publicKey = new byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKeyPair(Seed, secretKey, publicKey);

        Assert.Throws<ArgumentOutOfRangeException>(() => Ed25519ph.New().FinalizeAndSign(new byte[63], new byte[64]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Ed25519ph.New().FinalizeAndSign(new byte[65], new byte[64]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Ed25519ph.New().FinalizeAndSign(secretKey, new byte[63]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Ed25519ph.New().FinalizeAndVerify(new byte[31], Signature));
        Assert.Throws<ArgumentOutOfRangeException>(() => Ed25519ph.New().FinalizeAndVerify(publicKey, new byte[65]));

        var ph = Ed25519ph.New();
        ph.Update("ab"u8);
        var thrown = 0;
        try
        {
            ph.FinalizeAndSign(secretKey, new byte[63]);
        }
        catch (ArgumentOutOfRangeException)
        {
            thrown++;
        }

        try
        {
            ph.FinalizeAndVerify(new byte[31], Signature);
        }
        catch (ArgumentOutOfRangeException)
        {
            thrown++;
        }

        thrown.Is(2);
        ph.Update("c"u8);
        var signature = new byte[CryptoSign.SignatureSize];
        ph.FinalizeAndSign(secretKey, signature);
        signature.Is(Signature);
    }
}
