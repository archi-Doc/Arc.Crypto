// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// Provides helper methods for computing Ed25519 digital signatures.
/// </summary>
public static class XChaCha20
{
    public const int KeySizeInBytes = 32; // crypto_stream_xchacha20_KEYBYTES
    public const int NonceSizeInBytes = 24; // crypto_stream_xchacha20_NONCEBYTES

    public static void CreateKey(Span<byte> key)
    {
        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_stream_xchacha20_keygen(key);
    }

    public static void Xor(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> cipher)
    {
        if (nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_stream_xchacha20_xor(cipher, message, (ulong)message.Length, nonce, key);
    }

    public static void Xor2(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> cipher)
    {
        if (nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_stream_chacha20_xor(cipher, message, (ulong)message.Length, nonce, key);
    }
}
