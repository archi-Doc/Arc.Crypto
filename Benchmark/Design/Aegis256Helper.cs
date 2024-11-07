// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Benchmark;

/// <summary>
/// Provides helper methods for computing Ed25519 digital signatures.
/// </summary>
public static class Aegis256Helper
{
    public const int KeySizeInBytes = 32; // crypto_aead_aegis256_ABYTES
    public const int NonceSizeInBytes = 32; // crypto_aead_aegis256_NPUBBYTES
    public const int ASizeInBytes = 32; // crypto_aead_aegis256_ABYTES

    public static void Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> cipher, out ulong cipherLength)
    {
        if (nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_aead_aegis256_encrypt(cipher, out cipherLength, message, (ulong)message.Length, IntPtr.Zero, 0, IntPtr.Zero, nonce, key);
    }

    public static void Decrypt(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> message, out ulong messageLength)
    {
        if (nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_aead_aegis256_decrypt(message, out messageLength, IntPtr.Zero, cipher, (ulong)cipher.Length, IntPtr.Zero, 0, nonce, key);
    }
}
