// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Test;

#pragma warning disable SA1601 // Partial elements should be documented

internal static partial class LibsodiumInterops
{
    internal const string Name = "libsodium";

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aegis256_encrypt(Span<byte> c, out ulong clen_p, ReadOnlySpan<byte> m, ulong mlen, IntPtr ad, ulong adlen, IntPtr nsec, ReadOnlySpan<byte> npub, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aegis256_decrypt(Span<byte> m, out ulong mlen_p, IntPtr nsec, ReadOnlySpan<byte> c, ulong clen, IntPtr ad, ulong adlen, ReadOnlySpan<byte> npub, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aegis256_encrypt(Span<byte> c, out ulong clen_p, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> ad, ulong adlen, IntPtr nsec, ReadOnlySpan<byte> npub, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aegis128l_encrypt(Span<byte> c, out ulong clen_p, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> ad, ulong adlen, IntPtr nsec, ReadOnlySpan<byte> npub, ReadOnlySpan<byte> k);
}

/// <summary>
/// libsodium AEGIS-256 reference used to cross-check <see cref="Arc.Crypto.Aegis256"/> in tests.
/// </summary>
#pragma warning disable SA1202 // Elements should be ordered by access
public static class Aegis256Helper
#pragma warning restore SA1202 // Elements should be ordered by access
{
    public const int KeySizeInBytes = 32; // crypto_aead_aegis256_KEYBYTES
    public const int NonceSizeInBytes = 32; // crypto_aead_aegis256_NPUBBYTES
    public const int ASizeInBytes = 32; // crypto_aead_aegis256_ABYTES

    /// <summary>
    /// Encrypts <paramref name="message"/> with associated data and writes the ciphertext followed by the 32-byte tag.
    /// </summary>
    /// <param name="message">The plaintext.</param>
    /// <param name="associatedData">The associated data.</param>
    /// <param name="nonce">The nonce (32 bytes).</param>
    /// <param name="key">The key (32 bytes).</param>
    /// <param name="cipher">The buffer that receives the ciphertext and tag; at least the message length plus 32 bytes.</param>
    public static void Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> cipher)
    {
        if (nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        if (cipher.Length < message.Length + ASizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(cipher));
        }

        LibsodiumInterops.crypto_aead_aegis256_encrypt(cipher, out var cipherLength, message, (ulong)message.Length, associatedData, (ulong)associatedData.Length, IntPtr.Zero, nonce, key);
        if (cipherLength != (ulong)(message.Length + ASizeInBytes))
        {
            throw new InvalidOperationException();
        }
    }

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

/// <summary>
/// libsodium AEGIS-128L reference used to cross-check <see cref="Arc.Crypto.Aegis128L"/> in tests.
/// </summary>
public static class Aegis128LHelper
{
    public const int KeySizeInBytes = 16; // crypto_aead_aegis128l_KEYBYTES
    public const int NonceSizeInBytes = 16; // crypto_aead_aegis128l_NPUBBYTES
    public const int ASizeInBytes = 32; // crypto_aead_aegis128l_ABYTES

    /// <summary>
    /// Encrypts <paramref name="message"/> with associated data and writes the ciphertext followed by the 32-byte tag.
    /// </summary>
    /// <param name="message">The plaintext.</param>
    /// <param name="associatedData">The associated data.</param>
    /// <param name="nonce">The nonce (16 bytes).</param>
    /// <param name="key">The key (16 bytes).</param>
    /// <param name="cipher">The buffer that receives the ciphertext and tag; at least the message length plus 32 bytes.</param>
    public static void Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> cipher)
    {
        if (nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        if (cipher.Length < message.Length + ASizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(cipher));
        }

        LibsodiumInterops.crypto_aead_aegis128l_encrypt(cipher, out var cipherLength, message, (ulong)message.Length, associatedData, (ulong)associatedData.Length, IntPtr.Zero, nonce, key);
        if (cipherLength != (ulong)(message.Length + ASizeInBytes))
        {
            throw new InvalidOperationException();
        }
    }
}
