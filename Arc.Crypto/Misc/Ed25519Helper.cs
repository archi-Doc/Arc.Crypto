// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
        // Ed25519Operations.CreateKeyFromSeed(privateKeySeed, publicKey, expandedPrivateKey);
        LibsodiumInterops.crypto_sign_ed25519_seed_keypair(publicKey, expandedPrivateKey, privateKeySeed);
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

        LibsodiumInterops.crypto_sign_ed25519_detached(signature, out var signatureLength, message, (ulong)message.Length, expandedPrivateKey);
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
