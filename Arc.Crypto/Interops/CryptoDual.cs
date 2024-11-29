﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto.Ed25519;

namespace Arc.Crypto;

/// <summary>
/// A support class for making Ed25519 and Curve25519 public keys interchangeable.<br/>
/// Traditionally, it was possible to convert an Ed25519 public key to a Curve25519 public key, but the reverse was challenging.<br/>
/// By adding a sign bit to the Curve25519 key, reverse conversion is now possible.<br/>
/// As a result, it does not strictly adhere to the standard Curve25519 format.
/// </summary>
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
    /// Converts a signature secret key to a encryption secret key.
    /// </summary>
    /// <param name="signSecretKey64">The signature secret key. The size must be <see cref="CryptoSign.SecretKeySize"/>(64 bytes).</param>
    /// <param name="boxSecretKey32">A span to hold the encryption secret key. The size must be <see cref="CryptoBox.SecretKeySize"/>(32 bytes).</param>
    public static void SecretKey_SignToBox(ReadOnlySpan<byte> signSecretKey64, Span<byte> boxSecretKey32)
    {
        if (signSecretKey64.Length != CryptoSign.SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signSecretKey64), CryptoSign.SecretKeySize);
        }

        if (boxSecretKey32.Length != CryptoBox.SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxSecretKey32), CryptoBox.SecretKeySize);
        }

        // LibsodiumInterops.crypto_sign_ed25519_sk_to_curve25519(boxSecretKey, signSecretKey);
        Span<byte> hash = stackalloc byte[64];
        LibsodiumInterops.crypto_hash(hash, signSecretKey64.Slice(0, 32), 32); // Sha2Helper.Get512_Span(signSecretKey.Slice(0, 32), hash);
        hash.Slice(0, 32).CopyTo(boxSecretKey32);
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

        // return LibsodiumInterops.crypto_sign_ed25519_pk_to_curve25519(boxPublicKey32, signPublicKey32) == 0;

        Ed25519Internal.ge25519_frombytes_negate_vartime(out var a, signPublicKey32);
        var one = new fe25519(1);
        Ed25519Internal.fe25519_sub(out var xMinusOne, ref one, ref a.Y);
        Ed25519Internal.fe25519_add(out var xPlusOne, ref one, ref a.Y);
        Ed25519Internal.fe25519_invert(out var inv, ref xMinusOne);
        Ed25519Internal.fe25519_mul(out var res, ref xPlusOne, ref inv);
        Ed25519Internal.fe25519_tobytes(boxPublicKey32, ref res);

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

        Ed25519Internal.fe25519_frombytes(out var x, boxPublicKey32);
        var one = new fe25519(1);
        Ed25519Internal.fe25519_sub(out var xMinusOne, ref x, ref one);
        Ed25519Internal.fe25519_add(out var xPlusOne, ref x, ref one);
        Ed25519Internal.fe25519_invert(out var inv, ref xPlusOne);
        Ed25519Internal.fe25519_mul(out var res, ref xMinusOne, ref inv);
        Ed25519Internal.fe25519_tobytes(signPublicKey32, ref res);

        signPublicKey32[31] |= (byte)(0x80 & boxPublicKey32[31]);
    }

    public static bool BoxPublicKey_Equals(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> publicKey2)
    {
        if (publicKey.Length != CryptoBox.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), CryptoBox.PublicKeySize);
        }

        if (publicKey2.Length != CryptoBox.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey2), CryptoBox.PublicKeySize);
        }

        if (!publicKey.Slice(0, CryptoBox.PublicKeySize - 1).SequenceEqual(publicKey2.Slice(0, CryptoBox.PublicKeySize - 1)))
        {
            return false;
        }

        return (publicKey[CryptoBox.PublicKeySize - 1] & 0x7F) == (publicKey2[CryptoBox.PublicKeySize - 1] & 0x7F);
    }
}