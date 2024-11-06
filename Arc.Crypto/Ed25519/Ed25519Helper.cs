// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// Provides helper methods for computing Ed25519 digital signatures.
/// </summary>
public static class Ed25519Helper
{
    public const int SeedSizeInBytes = 32;
    public const int SecretKeySizeInBytes = 64;
    public const int PublicKeySizeInBytes = 32;
    public const int SignatureSizeInBytes = 64;

    public static void CreateKey(Span<byte> secretKey, Span<byte> publicKey)
    {
        if (publicKey.Length != PublicKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        if (secretKey.Length != SecretKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        LibsodiumInterops.crypto_sign_ed25519_keypair(publicKey, secretKey);
    }

    public static void CreateKey(ReadOnlySpan<byte> seed, Span<byte> secretKey, Span<byte> publicKey)
    {
        if (seed.Length != SeedSizeInBytes)
        {
            throw new ArgumentNullException(nameof(seed));
        }

        if (publicKey.Length != PublicKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        if (secretKey.Length != SecretKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        LibsodiumInterops.crypto_sign_ed25519_seed_keypair(publicKey, secretKey, seed);
    }

    public static void SecretKeyToSeed(ReadOnlySpan<byte> secretKey, Span<byte> seed)
    {
        if (secretKey.Length != SecretKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (seed.Length != SeedSizeInBytes)
        {
            throw new ArgumentNullException(nameof(seed));
        }

        LibsodiumInterops.crypto_sign_ed25519_sk_to_seed(seed, secretKey);
    }

    public static void SecretKeyToPublicKey(ReadOnlySpan<byte> secretKey, Span<byte> publicKey)
    {
        if (secretKey.Length != SecretKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (publicKey.Length != PublicKeySizeInBytes)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        LibsodiumInterops.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);
    }

    public static void Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> secretKey, Span<byte> signature)
    {
        if (secretKey.Length != SecretKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (signature.Length != SignatureSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(signature));
        }

        LibsodiumInterops.crypto_sign_ed25519_detached(signature, out var signatureLength, message, (ulong)message.Length, secretKey);
    }

    public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        if (signature.Length != SignatureSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(signature));
        }

        return LibsodiumInterops.crypto_sign_ed25519_verify_detached(signature, message, (ulong)message.Length, publicKey) == 0;
    }
}
