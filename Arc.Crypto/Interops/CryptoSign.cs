// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Drawing;

namespace Arc.Crypto;

/// <summary>
/// Helper class for calling crypto_sign function in Libsodium, which implements public-key signature algorithm.<br/>
/// Single-part signature: Ed25519, Multi-part signature: Ed25519ph.
/// </summary>
public static class CryptoSign
{
    public const int SeedSize = 32;
    public const int SecretKeySize = 64;
    public const int PublicKeySize = 32;
    public const int SignatureSize = 64;

    public static void CreateKey(Span<byte> secretKey, Span<byte> publicKey)
    {
        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (publicKey.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), PublicKeySize);
        }

        LibsodiumInterops.crypto_sign_keypair(publicKey, secretKey);
    }

    public static void CreateKey(ReadOnlySpan<byte> seed, Span<byte> secretKey, Span<byte> publicKey)
    {
        if (seed.Length != SeedSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(seed), SeedSize);
        }

        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (publicKey.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), PublicKeySize);
        }

        LibsodiumInterops.crypto_sign_seed_keypair(publicKey, secretKey, seed);
    }

    public static void SecretKeyToSeed(ReadOnlySpan<byte> secretKey, Span<byte> seed)
    {
        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (seed.Length < SeedSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(seed), SeedSize);
        }

        secretKey.Slice(0, SeedSize).CopyTo(seed); // LibsodiumInterops.crypto_sign_ed25519_sk_to_seed(seed, secretKey);
    }

    public static void SecretKeyToPublicKey(ReadOnlySpan<byte> secretKey, Span<byte> publicKey)
    {
        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (publicKey.Length < PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), PublicKeySize);
        }

        secretKey.Slice(SeedSize, PublicKeySize).CopyTo(publicKey); // LibsodiumInterops.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);
    }

    public static void SecretKey_SignToBox(ReadOnlySpan<byte> signSecretKey, Span<byte> boxSecretKey)
    {
        if (signSecretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signSecretKey), SecretKeySize);
        }

        if (boxSecretKey.Length != CryptoBox.SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxSecretKey), SecretKeySize);
        }

        // LibsodiumInterops.crypto_sign_ed25519_sk_to_curve25519(boxSecretKey, signSecretKey);
        Span<byte> hash = stackalloc byte[64];
        LibsodiumInterops.crypto_hash(hash, signSecretKey.Slice(0, 32), 32); // Sha2Helper.Get512_Span(signSecretKey.Slice(0, 32), hash);
        hash.Slice(0, 32).CopyTo(boxSecretKey);
    }

    public static void PublicKey_SignToBox(ReadOnlySpan<byte> signPublicKey, Span<byte> boxPublicKey)
    {
        if (signPublicKey.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signPublicKey), PublicKeySize);
        }

        if (boxPublicKey.Length != CryptoBox.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxPublicKey), CryptoBox.PublicKeySize);
        }

        LibsodiumInterops.crypto_sign_ed25519_pk_to_curve25519(boxPublicKey, signPublicKey);
    }

    public static void Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> secretKey, Span<byte> signature)
    {
        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (signature.Length != SignatureSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signature), SignatureSize);
        }

        LibsodiumInterops.crypto_sign_ed25519_detached(signature, out var signatureLength, message, (ulong)message.Length, secretKey);
    }

    public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), PublicKeySize);
        }

        if (signature.Length != SignatureSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signature), SignatureSize);
        }

        return LibsodiumInterops.crypto_sign_ed25519_verify_detached(signature, message, (ulong)message.Length, publicKey) == 0;
    }
}
