// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// Provides helper methods for computing Ed25519 digital signatures.
/// </summary>
public static class CryptoBoxHelper
{
    public const int KeySizeInBytes = 32;
    public const int NonceSizeInBytes = 24; // crypto_secretbox_xsalsa20poly1305_NONCEBYTES
    public const int MacSizeInBytes = 16; // crypto_secretbox_MACBYTES = crypto_secretbox_xsalsa20poly1305_MACBYTES

    public static void CreateKey(Span<byte> key)
    {
        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_secretbox_keygen(key);
    }

    public static void Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> cipher)
    {
        if (nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_secretbox_easy(cipher, message, (ulong)message.Length, nonce, key);
    }

    public static void Decrypt(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> message)
    {
        if (nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_secretbox_open_easy(message, cipher, (ulong)cipher.Length, nonce, key);
    }
}
