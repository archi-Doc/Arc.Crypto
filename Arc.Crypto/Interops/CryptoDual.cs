// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto.Ed25519;

namespace Arc.Crypto;

public static class CryptoDual
{
    public static void CreateKey(Span<byte> signSecretKey32, Span<byte> signPublicKey32, Span<byte> boxSecretKey32, Span<byte> boxPublicKey32)
    {
        Span<byte> seed = stackalloc byte[CryptoSign.SeedSize];
        CryptoRandom.NextBytes(seed);
        CreateKey(seed, signSecretKey32, signPublicKey32, boxSecretKey32, boxPublicKey32);
    }

    public static void CreateKey(ReadOnlySpan<byte> seed32, Span<byte> signSecretKey64, Span<byte> signPublicKey32, Span<byte> boxSecretKey32, Span<byte> boxPublicKey32)
    {
        if (seed32.Length != CryptoSign.SeedSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(seed32), CryptoSign.SeedSize);
        }

        if (signSecretKey64.Length != CryptoSign.SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signSecretKey64), CryptoSign.SecretKeySize);
        }

        if (signPublicKey32.Length != CryptoSign.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signPublicKey32), CryptoSign.PublicKeySize);
        }

        if (boxSecretKey32.Length != CryptoBox.SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxSecretKey32), CryptoBox.SecretKeySize);
        }

        if (boxPublicKey32.Length != CryptoBox.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxPublicKey32), CryptoBox.PublicKeySize);
        }

        LibsodiumInterops.crypto_sign_seed_keypair(signPublicKey32, signSecretKey64, seed32);
        LibsodiumInterops.crypto_box_seed_keypair(boxPublicKey32, boxSecretKey32, seed32);

        boxPublicKey32[31] |= (byte)(0x80 & signPublicKey32[31]);
    }

    /// <summary>
    /// Converts a signature public key to an encryption public key.
    /// </summary>
    /// <param name="signPublicKey32">The signature public key. The size must be <see cref="CryptoSign.PublicKeySize"/>(32 bytes).</param>
    /// <param name="boxPublicKey32">A span to hold the encryption public key. The size must be <see cref="CryptoBox.PublicKeySize"/>(32 bytes).</param>
    public static void PublicKey_SignToBox(ReadOnlySpan<byte> signPublicKey32, Span<byte> boxPublicKey32)
    {
        if (signPublicKey32.Length != CryptoSign.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signPublicKey32), CryptoSign.PublicKeySize);
        }

        if (boxPublicKey32.Length != CryptoBox.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxPublicKey32), CryptoBox.PublicKeySize);
        }

        Ed25519Helper.ge25519_frombytes_negate_vartime(out var a, signPublicKey32);
        var one = new fe25519(1);
        Ed25519Helper.fe25519_sub(out var xMinusOne, ref one, ref a.Y);
        Ed25519Helper.fe25519_add(out var xPlusOne, ref one, ref a.Y);
        Ed25519Helper.fe25519_invert(out var inv, ref xMinusOne);
        Ed25519Helper.fe25519_mul(out var res, ref xPlusOne, ref inv);
        Ed25519Helper.fe25519_tobytes(boxPublicKey32, ref res);

        boxPublicKey32[31] |= (byte)(0x80 & signPublicKey32[31]);
    }

    public static void PublicKey_BoxToSign(ReadOnlySpan<byte> boxPublicKey32, Span<byte> signPublicKey32)
    {
        if (boxPublicKey32.Length != CryptoBox.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxPublicKey32), CryptoBox.PublicKeySize);
        }

        if (signPublicKey32.Length != CryptoSign.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signPublicKey32), CryptoSign.PublicKeySize);
        }

        Ed25519Helper.fe25519_frombytes(out var x, boxPublicKey32);
        var one = new fe25519(1);
        Ed25519Helper.fe25519_sub(out var xMinusOne, ref x, ref one);
        Ed25519Helper.fe25519_add(out var xPlusOne, ref x, ref one);
        Ed25519Helper.fe25519_invert(out var inv, ref xPlusOne);
        Ed25519Helper.fe25519_mul(out var res, ref xMinusOne, ref inv);
        Ed25519Helper.fe25519_tobytes(signPublicKey32, ref res);

        signPublicKey32[31] |= (byte)(0x80 & boxPublicKey32[31]);
    }
}
