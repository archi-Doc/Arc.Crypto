// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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

    public static void RandomBytes(Span<byte> buffer)
    {
        LibsodiumInterops.randombytes_buf(buffer, (int)buffer.Length);
    }

    public static uint RandomUInt32()
    {
        return LibsodiumInterops.randombytes_random();
    }

    public static void CreateKey(Span<byte> secretKey, Span<byte> publicKey)
    {
        if (secretKey.Length != SecretKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (publicKey.Length != PublicKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        LibsodiumInterops.crypto_sign_keypair(publicKey, secretKey);
    }

    public static void CreateKey(ReadOnlySpan<byte> seed, Span<byte> secretKey, Span<byte> publicKey)
    {
        if (seed.Length != SeedSize)
        {
            throw new ArgumentNullException(nameof(seed));
        }

        if (secretKey.Length != SecretKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (publicKey.Length != PublicKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        LibsodiumInterops.crypto_sign_seed_keypair(publicKey, secretKey, seed);
    }

    public static void SecretKeyToSeed(ReadOnlySpan<byte> secretKey, Span<byte> seed)
    {
        if (secretKey.Length != SecretKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (seed.Length < SeedSize)
        {
            throw new ArgumentNullException(nameof(seed));
        }

        secretKey.Slice(0, SeedSize).CopyTo(seed); // LibsodiumInterops.crypto_sign_ed25519_sk_to_seed(seed, secretKey);
    }

    public static void SecretKeyToPublicKey(ReadOnlySpan<byte> secretKey, Span<byte> publicKey)
    {
        if (secretKey.Length != SecretKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (publicKey.Length < PublicKeySize)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        secretKey.Slice(SeedSize, PublicKeySize).CopyTo(publicKey); // LibsodiumInterops.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);
    }

    public static void SecretKey_SignToBox(ReadOnlySpan<byte> signSecretKey, Span<byte> boxSecretKey)
    {
        if (signSecretKey.Length != SecretKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(signSecretKey));
        }

        if (boxSecretKey.Length != CryptoBox.SecretKeySize)
        {
            throw new ArgumentNullException(nameof(boxSecretKey));
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
            throw new ArgumentOutOfRangeException(nameof(signPublicKey));
        }

        if (boxPublicKey.Length != CryptoBox.PublicKeySize)
        {
            throw new ArgumentNullException(nameof(boxPublicKey));
        }

        LibsodiumInterops.crypto_sign_ed25519_pk_to_curve25519(boxPublicKey, signPublicKey);
    }

    public static void Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> secretKey, Span<byte> signature)
    {
        if (secretKey.Length != SecretKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (signature.Length != SignatureSize)
        {
            throw new ArgumentOutOfRangeException(nameof(signature));
        }

        LibsodiumInterops.crypto_sign_ed25519_detached(signature, out var signatureLength, message, (ulong)message.Length, secretKey);
    }

    public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        if (signature.Length != SignatureSize)
        {
            throw new ArgumentOutOfRangeException(nameof(signature));
        }

        return LibsodiumInterops.crypto_sign_ed25519_verify_detached(signature, message, (ulong)message.Length, publicKey) == 0;
    }
}
