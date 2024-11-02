// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto.Ed25519;

namespace Arc.Crypto;

public static class Ed25519Helper
{
    public const int PublicKeySizeInBytes = 32;
    public const int SignatureSizeInBytes = 64;
    public const int ExpandedPrivateKeySizeInBytes = 32 * 2;
    public const int PrivateKeySeedSizeInBytes = 32;
    public const int SharedKeySizeInBytes = 32;

    public static void KeyPairFromSeed(ReadOnlySpan<byte> privateKeySeed, out byte[] publicKey, out byte[] expandedPrivateKey)
    {
        if (privateKeySeed.Length != PrivateKeySeedSizeInBytes)
        {
            throw new ArgumentNullException(nameof(privateKeySeed));
        }

        publicKey = new byte[PublicKeySizeInBytes];
        expandedPrivateKey = new byte[ExpandedPrivateKeySizeInBytes];
        Ed25519Operations.crypto_sign_keypair(privateKeySeed, publicKey, expandedPrivateKey);
    }

    public static void Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> expandedPrivateKey, Span<byte> signature)
    {
        if (expandedPrivateKey.Length != ExpandedPrivateKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(expandedPrivateKey));
        }

        if (signature.Length != SignatureSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(signature));
        }

        Ed25519Operations.crypto_sign2(signature, message, expandedPrivateKey);
    }
}
