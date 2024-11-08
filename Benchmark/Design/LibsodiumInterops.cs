// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Benchmark;

#pragma warning disable SA1202 // Elements should be ordered by access

internal static partial class LibsodiumInterops
{
    internal const string Name = "libsodium";

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_hash(scoped Span<byte> @out, scoped ReadOnlySpan<byte> @in, ulong inlen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aegis256_encrypt(Span<byte> c, out ulong clen_p, ReadOnlySpan<byte> m, ulong mlen, IntPtr ad, ulong adlen, IntPtr nsec, ReadOnlySpan<byte> npub, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aegis256_decrypt(Span<byte> m, out ulong mlen_p, IntPtr nsec, ReadOnlySpan<byte> c, ulong clen, IntPtr ad, ulong adlen, ReadOnlySpan<byte> npub, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void crypto_stream_xchacha20_keygen(scoped Span<byte> key);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_stream_xchacha20(Span<byte> c, ulong clen, ReadOnlySpan<byte> n, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_stream_xchacha20_xor(Span<byte> c, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> n, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_stream_chacha20_xor(Span<byte> c, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> n, ReadOnlySpan<byte> k);
}

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

/// <summary>
/// Provides helper methods for computing Ed25519 digital signatures.
/// </summary>
#pragma warning disable SA1202 // Elements should be ordered by access
public static class Aegis256Helper
#pragma warning restore SA1202 // Elements should be ordered by access
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
