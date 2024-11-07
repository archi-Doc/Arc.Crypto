// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Arc.Crypto;

/// <summary>
/// Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305.
/// </summary>
public static class CryptoBoxHelper
{
    public const int SeedSizeInBytes = 32; // crypto_box_SEEDBYTES = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
    public const int SecretKeySizeInBytes = 32; // crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
    public const int PublicKeySizeInBytes = 32; // crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
    public const int NonceSizeInBytes = 24; // crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
    public const int MacSizeInBytes = 16; // crypto_box_curve25519xsalsa20poly1305_MACBYTES 

    public static void CreateKey(Span<byte> secretKey, Span<byte> publicKey)
    {
        if (secretKey.Length != SecretKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (publicKey.Length != PublicKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        LibsodiumInterops.crypto_box_keypair(publicKey, secretKey);
    }

    public static void CreateKey(ReadOnlySpan<byte> seed, Span<byte> secretKey, Span<byte> publicKey)
    {
        if (seed.Length != SeedSizeInBytes)
        {
            throw new ArgumentNullException(nameof(seed));
        }

        if (secretKey.Length != SecretKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        if (publicKey.Length != PublicKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        LibsodiumInterops.crypto_box_seed_keypair(publicKey, secretKey, seed);
    }
}
