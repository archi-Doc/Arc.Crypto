// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

// ============================================================================
//  FastBase64.cs
//
//  High-performance Base64 / Base64Url encoding and decoding for x86/x64
//  using SIMD intrinsics (SSE2 / SSSE3 / SSE4.1 / AVX / AVX2).
//
//  The algorithm is based on the SIMD Base64 technique by Wojciech Muła et al.
//  ("Base64 encoding and decoding at almost the speed of a memory copy"),
//  as proven in aklomp/base64 and the .NET runtime:
//
//      Encode: 24 bytes -> 32 chars per loop (AVX2), 12 -> 16 (SSSE3)
//      Decode: 32 chars -> 24 bytes per loop (AVX2), 16 -> 12 (SSSE3)
//
//  - The fastest available path (AVX2 / SSSE3+SSE4.1 / SSSE3 / scalar) is
//    selected at run time. SSE4.2 string instructions offer no benefit for
//    Base64, so validation uses the SSE4.1 `ptest` instruction, falling back
//    to SSE2 `pmovmskb` on older CPUs.
//  - Both alphabets are implemented through zero-cost generic specialization
//    (a value-type parameter with static abstract members): the JIT compiles
//    a dedicated body per alphabet, so there is no per-call branching.
//  - FastBase64:    standard alphabet (A-Z a-z 0-9 + /), '=' padded output.
//  - FastBase64Url: URL-safe alphabet (A-Z a-z 0-9 - _), unpadded output
//    (RFC 4648 section 5); decoding accepts both padded and unpadded input.
//  - Decoding is strict: whitespace is not accepted.
//  - Requires .NET 7+ (static abstract interface members); .NET 8 recommended.
// ============================================================================

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Arc.Crypto;

#pragma warning disable SA1117
#pragma warning disable SA1519 // Braces should not be omitted from multi-line child statement
#pragma warning disable SA1202 // Elements should be ordered by access

/// <summary>
/// High-performance Base64 codec using the standard alphabet
/// (<c>A-Z a-z 0-9 + /</c>) with <c>'='</c> padding (RFC 4648 section 4).
/// </summary>
public static unsafe class Base64
{
    /// <summary>
    /// Returns the exact number of characters produced by encoding
    /// <paramref name="byteCount"/> bytes, including padding.
    /// </summary>
    /// <param name="byteCount">Number of input bytes.</param>
    /// <returns>Encoded length in characters (always a multiple of 4).</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="byteCount"/> is negative, or the result exceeds <see cref="int.MaxValue"/>.
    /// </exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(int byteCount)
    {
        if (byteCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCount));
        }

        long len = ((long)byteCount + 2) / 3 * 4;
        if (len > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCount), "Encoded length exceeds Int32.MaxValue.");
        }

        return (int)len;
    }

    /// <summary>
    /// Returns an upper bound for the number of bytes produced by decoding an
    /// encoded sequence of <paramref name="encodedLength"/> characters.
    /// Safe to use as a destination buffer size for padded or unpadded input.
    /// </summary>
    /// <param name="encodedLength">Length of the encoded input in characters.</param>
    /// <returns>Maximum decoded length in bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="encodedLength"/> is negative.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetMaxDecodedLength(int encodedLength)
    {
        if (encodedLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedLength));
        }

        return (int)((long)encodedLength * 3 / 4);
    }

    /// <summary>
    /// Returns the exact number of bytes produced by decoding
    /// <paramref name="utf8"/> (trailing <c>'='</c> padding is inspected).
    /// </summary>
    /// <param name="utf8">Encoded input as UTF-8/ASCII bytes.</param>
    /// <returns>Exact decoded length in bytes.</returns>
    /// <exception cref="FormatException">The input length is not a valid Base64 length.</exception>
    public static int GetDecodedLength(ReadOnlySpan<byte> utf8) =>
        B64.GetDecodedLength(utf8);

    /// <inheritdoc cref="GetDecodedLength(ReadOnlySpan{byte})"/>
    /// <param name="chars">Encoded input as UTF-16 characters.</param>
    public static int GetDecodedLength(ReadOnlySpan<char> chars) =>
        B64.GetDecodedLength(chars);

    /// <summary>
    /// Encodes <paramref name="bytes"/> into UTF-8/ASCII Base64 text.
    /// </summary>
    /// <param name="bytes">Input data.</param>
    /// <param name="utf8Destination">Destination buffer; must hold at least
    /// <see cref="GetEncodedLength(int)"/> bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">The destination buffer is too small.</exception>
    public static int Encode(ReadOnlySpan<byte> bytes, Span<byte> utf8Destination) =>
        B64.EncodeToUtf8<B64.Std>(bytes, utf8Destination, GetEncodedLength(bytes.Length));

    /// <summary>
    /// Encodes <paramref name="bytes"/> into UTF-16 Base64 text.
    /// </summary>
    /// <param name="bytes">Input data.</param>
    /// <param name="charsDestination">Destination buffer; must hold at least
    /// <see cref="GetEncodedLength(int)"/> characters.</param>
    /// <returns>The number of characters written.</returns>
    /// <exception cref="ArgumentException">The destination buffer is too small.</exception>
    public static int Encode(ReadOnlySpan<byte> bytes, Span<char> charsDestination) =>
        B64.EncodeToChars<B64.Std>(bytes, charsDestination, GetEncodedLength(bytes.Length));

    /// <summary>
    /// Encodes <paramref name="bytes"/> into a new Base64 <see cref="string"/>.
    /// </summary>
    /// <param name="bytes">Input data.</param>
    /// <returns>The encoded string.</returns>
    public static string EncodeToString(ReadOnlySpan<byte> bytes) =>
        B64.EncodeToString<B64.Std>(bytes, GetEncodedLength(bytes.Length));

    /// <summary>
    /// Attempts to decode Base64 text given as UTF-8/ASCII bytes.
    /// </summary>
    /// <param name="utf8">Encoded input (padded or unpadded).</param>
    /// <param name="bytesDestination">Destination buffer for the decoded bytes.</param>
    /// <param name="bytesWritten">Receives the number of bytes written.</param>
    /// <returns><see langword="false"/> if the input is invalid or the destination is too small.</returns>
    public static bool TryDecode(ReadOnlySpan<byte> utf8, Span<byte> bytesDestination, out int bytesWritten) =>
        B64.TryDecodeUtf8<B64.Std>(utf8, bytesDestination, out bytesWritten);

    /// <summary>
    /// Attempts to decode Base64 text given as UTF-16 characters.
    /// </summary>
    /// <param name="chars">Encoded input (padded or unpadded).</param>
    /// <param name="bytesDestination">Destination buffer for the decoded bytes.</param>
    /// <param name="bytesWritten">Receives the number of bytes written.</param>
    /// <returns><see langword="false"/> if the input is invalid or the destination is too small.</returns>
    public static bool TryDecode(ReadOnlySpan<char> chars, Span<byte> bytesDestination, out int bytesWritten) =>
        B64.TryDecodeChars<B64.Std>(chars, bytesDestination, out bytesWritten);

    /// <summary>
    /// Decodes Base64 text given as UTF-8/ASCII bytes.
    /// </summary>
    /// <param name="utf8">Encoded input (padded or unpadded).</param>
    /// <param name="bytesDestination">Destination buffer for the decoded bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="FormatException">The input is not valid Base64, or the destination is too small.</exception>
    public static int Decode(ReadOnlySpan<byte> utf8, Span<byte> bytesDestination)
    {
        if (!TryDecode(utf8, bytesDestination, out int written))
        {
            B64.ThrowInvalidBase64();
        }

        return written;
    }

    /// <summary>
    /// Decodes Base64 text given as UTF-16 characters.
    /// </summary>
    /// <param name="chars">Encoded input (padded or unpadded).</param>
    /// <param name="bytesDestination">Destination buffer for the decoded bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="FormatException">The input is not valid Base64, or the destination is too small.</exception>
    public static int Decode(ReadOnlySpan<char> chars, Span<byte> bytesDestination)
    {
        if (!TryDecode(chars, bytesDestination, out int written))
        {
            B64.ThrowInvalidBase64();
        }

        return written;
    }

    /// <summary>
    /// Decodes a Base64 <see cref="string"/> into a new byte array.
    /// </summary>
    /// <param name="base64">Encoded input (padded or unpadded).</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="FormatException">The input is not valid Base64.</exception>
    public static byte[] Decode(string base64)
    {
        ArgumentNullException.ThrowIfNull(base64);
        return B64.DecodeToArray<B64.Std>(base64);
    }
}

/// <summary>
/// High-performance Base64 codec using the URL- and filename-safe alphabet
/// (<c>A-Z a-z 0-9 - _</c>, RFC 4648 section 5). Encoding emits no padding;
/// decoding accepts both padded and unpadded input.
/// </summary>
public static unsafe class Base64Url
{
    /// <summary>
    /// Returns the exact number of characters produced by encoding
    /// <paramref name="byteCount"/> bytes (no padding is emitted).
    /// </summary>
    /// <param name="byteCount">Number of input bytes.</param>
    /// <returns>Encoded length in characters.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="byteCount"/> is negative, or the result exceeds <see cref="int.MaxValue"/>.
    /// </exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(int byteCount)
    {
        if (byteCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCount));
        }

        long len = (((long)byteCount * 4) + 2) / 3; // ceil(4n/3)
        if (len > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCount), "Encoded length exceeds Int32.MaxValue.");
        }

        return (int)len;
    }

    /// <summary>
    /// Returns an upper bound for the number of bytes produced by decoding an
    /// encoded sequence of <paramref name="encodedLength"/> characters.
    /// Safe to use as a destination buffer size for padded or unpadded input.
    /// </summary>
    /// <param name="encodedLength">Length of the encoded input in characters.</param>
    /// <returns>Maximum decoded length in bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="encodedLength"/> is negative.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetMaxDecodedLength(int encodedLength)
    {
        if (encodedLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedLength));
        }

        return (int)((long)encodedLength * 3 / 4);
    }

    /// <summary>
    /// Returns the exact number of bytes produced by decoding
    /// <paramref name="utf8"/> (trailing <c>'='</c> padding is inspected).
    /// </summary>
    /// <param name="utf8">Encoded input as UTF-8/ASCII bytes.</param>
    /// <returns>Exact decoded length in bytes.</returns>
    /// <exception cref="FormatException">The input length is not a valid Base64Url length.</exception>
    public static int GetDecodedLength(ReadOnlySpan<byte> utf8) =>
        B64.GetDecodedLength(utf8);

    /// <inheritdoc cref="GetDecodedLength(ReadOnlySpan{byte})"/>
    /// <param name="chars">Encoded input as UTF-16 characters.</param>
    public static int GetDecodedLength(ReadOnlySpan<char> chars) =>
         B64.GetDecodedLength(chars);

    /// <summary>
    /// Encodes <paramref name="bytes"/> into UTF-8/ASCII Base64Url text (unpadded).
    /// </summary>
    /// <param name="bytes">Input data.</param>
    /// <param name="utf8Destination">Destination buffer; must hold at least
    /// <see cref="GetEncodedLength(int)"/> bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">The destination buffer is too small.</exception>
    public static int Encode(ReadOnlySpan<byte> bytes, Span<byte> utf8Destination) =>
        B64.EncodeToUtf8<B64.Url>(bytes, utf8Destination, GetEncodedLength(bytes.Length));

    /// <summary>
    /// Encodes <paramref name="bytes"/> into UTF-16 Base64Url text (unpadded).
    /// </summary>
    /// <param name="bytes">Input data.</param>
    /// <param name="charsDestination">Destination buffer; must hold at least
    /// <see cref="GetEncodedLength(int)"/> characters.</param>
    /// <returns>The number of characters written.</returns>
    /// <exception cref="ArgumentException">The destination buffer is too small.</exception>
    public static int Encode(ReadOnlySpan<byte> bytes, Span<char> charsDestination) =>
        B64.EncodeToChars<B64.Url>(bytes, charsDestination, GetEncodedLength(bytes.Length));

    /// <summary>
    /// Encodes <paramref name="bytes"/> into a new Base64Url <see cref="string"/> (unpadded).
    /// </summary>
    /// <param name="bytes">Input data.</param>
    /// <returns>The encoded string.</returns>
    public static string EncodeToString(ReadOnlySpan<byte> bytes) =>
        B64.EncodeToString<B64.Url>(bytes, GetEncodedLength(bytes.Length));

    /// <summary>
    /// Attempts to decode Base64Url text given as UTF-8/ASCII bytes.
    /// </summary>
    /// <param name="utf8">Encoded input (padded or unpadded).</param>
    /// <param name="bytesDestination">Destination buffer for the decoded bytes.</param>
    /// <param name="bytesWritten">Receives the number of bytes written.</param>
    /// <returns><see langword="false"/> if the input is invalid or the destination is too small.</returns>
    public static bool TryDecode(ReadOnlySpan<byte> utf8, Span<byte> bytesDestination, out int bytesWritten) =>
        B64.TryDecodeUtf8<B64.Url>(utf8, bytesDestination, out bytesWritten);

    /// <summary>
    /// Attempts to decode Base64Url text given as UTF-16 characters.
    /// </summary>
    /// <param name="chars">Encoded input (padded or unpadded).</param>
    /// <param name="bytesDestination">Destination buffer for the decoded bytes.</param>
    /// <param name="bytesWritten">Receives the number of bytes written.</param>
    /// <returns><see langword="false"/> if the input is invalid or the destination is too small.</returns>
    public static bool TryDecode(ReadOnlySpan<char> chars, Span<byte> bytesDestination, out int bytesWritten) =>
        B64.TryDecodeChars<B64.Url>(chars, bytesDestination, out bytesWritten);

    /// <summary>
    /// Decodes Base64Url text given as UTF-8/ASCII bytes.
    /// </summary>
    /// <param name="utf8">Encoded input (padded or unpadded).</param>
    /// <param name="bytesDestination">Destination buffer for the decoded bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="FormatException">The input is not valid Base64Url, or the destination is too small.</exception>
    public static int Decode(ReadOnlySpan<byte> utf8, Span<byte> bytesDestination)
    {
        if (!TryDecode(utf8, bytesDestination, out int written))
        {
            B64.ThrowInvalidBase64();
        }

        return written;
    }

    /// <summary>
    /// Decodes Base64Url text given as UTF-16 characters.
    /// </summary>
    /// <param name="chars">Encoded input (padded or unpadded).</param>
    /// <param name="bytesDestination">Destination buffer for the decoded bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="FormatException">The input is not valid Base64Url, or the destination is too small.</exception>
    public static int Decode(ReadOnlySpan<char> chars, Span<byte> bytesDestination)
    {
        if (!TryDecode(chars, bytesDestination, out int written))
        {
            B64.ThrowInvalidBase64();
        }

        return written;
    }

    /// <summary>
    /// Decodes a Base64Url <see cref="string"/> into a new byte array.
    /// </summary>
    /// <param name="base64Url">Encoded input (padded or unpadded).</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="FormatException">The input is not valid Base64Url.</exception>
    public static byte[] Decode(string base64Url)
    {
        ArgumentNullException.ThrowIfNull(base64Url);
        return B64.DecodeToArray<B64.Url>(base64Url);
    }
}

// ============================================================================
//  Shared implementation core.
//
//  The alphabet is a value-type generic parameter with a static abstract
//  member, so `T.IsUrl` is a JIT-time constant: each alphabet gets its own
//  fully specialized native code with the unused branches eliminated.
// ============================================================================
internal static unsafe class B64
{
    internal interface IAlphabet
    {
        static abstract bool IsUrl { get; }
    }

    internal struct Std : IAlphabet
    {
        public static bool IsUrl => false;
    }

    internal struct Url : IAlphabet
    {
        public static bool IsUrl => true;
    }

    internal static int GetDecodedLength(ReadOnlySpan<byte> s)
    {
        int trimmedLength = TrimPadding(s, out bool ok);
        if (!ok)
        {
            throw new FormatException("Invalid Base64 padding.");
        }

        return ExactDecodedLength(trimmedLength);
    }

    internal static int GetDecodedLength(ReadOnlySpan<char> s)
    {
        int trimmedLength = TrimPadding(s, out bool ok);
        if (!ok)
        {
            throw new FormatException("Invalid Base64 padding.");
        }

        return ExactDecodedLength(trimmedLength);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static void ThrowInvalidBase64() =>
        throw new FormatException("The input is not a valid Base64 sequence, or the destination buffer is too small.");

    // Returns the length without trailing '=' (at most 2). If padding is
    // present but the total length is not a multiple of 4, ok = false.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int TrimPadding(ReadOnlySpan<byte> s, out bool ok)
    {
        int len = s.Length;
        int trimmed = len;
        if (trimmed > 0 && s[trimmed - 1] == (byte)'=')
        {
            trimmed--;
            if (trimmed > 0 && s[trimmed - 1] == (byte)'=')
            {
                trimmed--;
            }
        }

        ok = trimmed == len || (len & 3) == 0;
        return trimmed;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int TrimPadding(ReadOnlySpan<char> s, out bool ok)
    {
        int len = s.Length;
        int trimmed = len;
        if (trimmed > 0 && s[trimmed - 1] == '=')
        {
            trimmed--;
            if (trimmed > 0 && s[trimmed - 1] == '=')
            {
                trimmed--;
            }
        }

        ok = trimmed == len || (len & 3) == 0;
        return trimmed;
    }

    // Unpadded length -> exact decoded byte count; -1 if the length is invalid
    // (length % 4 == 1 can never occur in valid Base64).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int DecodedLength(int trimmedLength)
    {
        int rem = trimmedLength & 3;
        if (rem == 1)
        {
            return -1;
        }

        return ((trimmedLength >> 2) * 3) + (rem == 0 ? 0 : rem - 1);
    }

    internal static int ExactDecodedLength(int trimmedLength)
    {
        int r = DecodedLength(trimmedLength);
        if (r < 0)
        {
            throw new FormatException("Invalid Base64 length.");
        }

        return r;
    }

    // ------------------------------------------------------------------
    // Lookup tables (embedded as RVA static data; no allocation)
    // ------------------------------------------------------------------

    private static ReadOnlySpan<byte> EncodingMap =>
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"u8;

    private static ReadOnlySpan<byte> UrlEncodingMap =>
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"u8;

    // ASCII -> 6-bit value; -1 marks an invalid character.
    private static ReadOnlySpan<sbyte> DecodingMap => new sbyte[256]
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0- 15
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16- 31
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, // 32- 47  '+' '/'
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, // 48- 63  '0'-'9'
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 64- 79  'A'-'O'
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 80- 95  'P'-'Z'
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 96-111  'a'-'o'
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 112-127  'p'-'z'
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    private static ReadOnlySpan<sbyte> UrlDecodingMap => new sbyte[256]
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0- 15
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16- 31
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, // 32- 47  '-'
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, // 48- 63  '0'-'9'
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 64- 79  'A'-'O'
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, // 80- 95  'P'-'Z' '_'
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 96-111  'a'-'o'
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 112-127  'p'-'z'
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    // ------------------------------------------------------------------
    // Public-API plumbing (pin spans, dispatch to the pointer cores)
    // ------------------------------------------------------------------

    internal static int EncodeToUtf8<T>(ReadOnlySpan<byte> bytes, Span<byte> dest, int encodedLength)
        where T : struct, IAlphabet
    {
        if (dest.Length < encodedLength)
        {
            throw new ArgumentException("Destination is too small.", nameof(dest));
        }

        if (bytes.IsEmpty)
        {
            return 0;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        fixed (byte* dst = &MemoryMarshal.GetReference(dest))
        {
            EncodeBytes<T>(src, bytes.Length, dst);
        }

        return encodedLength;
    }

    internal static int EncodeToChars<T>(ReadOnlySpan<byte> bytes, Span<char> dest, int encodedLength)
        where T : struct, IAlphabet
    {
        if (dest.Length < encodedLength)
        {
            throw new ArgumentException("Destination is too small.", nameof(dest));
        }

        if (bytes.IsEmpty)
        {
            return 0;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        fixed (char* dst = &MemoryMarshal.GetReference(dest))
        {
            EncodeChars<T>(src, bytes.Length, dst);
        }

        return encodedLength;
    }

    internal static string EncodeToString<T>(ReadOnlySpan<byte> bytes, int encodedLength)
        where T : struct, IAlphabet
    {
        if (bytes.IsEmpty)
        {
            return string.Empty;
        }

        // Write directly into a freshly allocated string (equivalent to the
        // string.Create idiom; the string is not yet visible to anyone else).
        string result = new string('\0', encodedLength);
        fixed (char* dst = result)
        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        {
            EncodeChars<T>(src, bytes.Length, dst);
        }

        return result;
    }

    internal static bool TryDecodeUtf8<T>(ReadOnlySpan<byte> utf8, Span<byte> dest, out int bytesWritten)
        where T : struct, IAlphabet
    {
        bytesWritten = 0;
        int len = TrimPadding(utf8, out bool ok);
        if (!ok)
        {
            return false;
        }

        int required = DecodedLength(len);
        if (required < 0 || dest.Length < required)
        {
            return false;
        }

        if (len == 0)
        {
            return true;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(utf8))
        fixed (byte* dst = &MemoryMarshal.GetReference(dest))
        {
            if (!DecodeUtf8<T>(src, len, dst, dst + dest.Length))
            {
                return false;
            }
        }

        bytesWritten = required;
        return true;
    }

    internal static bool TryDecodeChars<T>(ReadOnlySpan<char> chars, Span<byte> dest, out int bytesWritten)
        where T : struct, IAlphabet
    {
        bytesWritten = 0;
        int len = TrimPadding(chars, out bool ok);
        if (!ok)
        {
            return false;
        }

        int required = DecodedLength(len);
        if (required < 0 || dest.Length < required)
        {
            return false;
        }

        if (len == 0)
        {
            return true;
        }

        fixed (char* src = &MemoryMarshal.GetReference(chars))
        fixed (byte* dst = &MemoryMarshal.GetReference(dest))
        {
            if (!DecodeChars<T>(src, len, dst, dst + dest.Length))
            {
                return false;
            }
        }

        bytesWritten = required;
        return true;
    }

    internal static byte[] DecodeToArray<T>(string s)
        where T : struct, IAlphabet
    {
        ReadOnlySpan<char> chars = s;
        int required = ExactDecodedLength(TrimPadding(chars, out bool ok));
        if (!ok)
        {
            throw new FormatException("Invalid Base64 padding.");
        }

        if (required == 0)
        {
            return Array.Empty<byte>();
        }

        byte[] result = new byte[required];
        if (!TryDecodeChars<T>(chars, result, out _))
        {
            ThrowInvalidBase64();
        }

        return result;
    }

    // ------------------------------------------------------------------
    // Encode core: shared SIMD transform (Muła's method)
    //
    //   Place 3 input bytes into each 32-bit lane as [b1, b0, b2, b1] (LE),
    //   split them into four 6-bit indices with AND + multiply-shift tricks,
    //   then map the indices to ASCII with saturating-subtract + pshufb LUT.
    // ------------------------------------------------------------------

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<sbyte> EncodeVector256<T>(Vector256<sbyte> str)
        where T : struct, IAlphabet
    {
        // Shuffle that places 3 source bytes into each lane as [b1,b0,b2,b1].
        Vector256<sbyte> shuffleVec = Vector256.Create(
            (sbyte)5, 4, 6, 5, 8, 7, 9, 8, 11, 10, 12, 11, 14, 13, 15, 14,
            1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);

        Vector256<sbyte> maskAC = Vector256.Create(0x0FC0FC00).AsSByte();
        Vector256<sbyte> maskBB = Vector256.Create(0x003F03F0).AsSByte();
        Vector256<ushort> shiftAC = Vector256.Create(0x04000040).AsUInt16();
        Vector256<short> shiftBB = Vector256.Create(0x01000010).AsInt16();

        // 6-bit value -> ASCII delta LUT. Entry 12 maps value 62, entry 13
        // maps value 63; only those two differ between the alphabets.
        Vector256<sbyte> lut = T.IsUrl
            ? Vector256.Create(
                (sbyte)65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -17, 32, 0, 0,
                65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -17, 32, 0, 0)
            : Vector256.Create(
                (sbyte)65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0,
                65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0);
        Vector256<sbyte> const51 = Vector256.Create((sbyte)51);
        Vector256<sbyte> const25 = Vector256.Create((sbyte)25);

        str = Avx2.Shuffle(str, shuffleVec);

        Vector256<sbyte> t0 = Avx2.And(str, maskAC);
        Vector256<sbyte> t2 = Avx2.And(str, maskBB);
        Vector256<ushort> t1 = Avx2.MultiplyHigh(t0.AsUInt16(), shiftAC);
        Vector256<short> t3 = Avx2.MultiplyLow(t2.AsInt16(), shiftBB);
        str = Avx2.Or(t1.AsSByte(), t3.AsSByte()); // every byte = 6-bit index (0..63)

        // LUT index: 0 for 0..25, 1 for 26..51, 2..11 for 52..61, 12 for 62, 13 for 63.
        Vector256<byte> indices = Avx2.SubtractSaturate(str.AsByte(), const51.AsByte());
        Vector256<sbyte> mask = Avx2.CompareGreaterThan(str, const25);
        Vector256<sbyte> lutIdx = Avx2.Subtract(indices.AsSByte(), mask);
        return Avx2.Add(str, Avx2.Shuffle(lut, lutIdx));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<sbyte> EncodeVector128<T>(Vector128<sbyte> str)
        where T : struct, IAlphabet
    {
        Vector128<sbyte> shuffleVec = Vector128.Create(
            (sbyte)1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);

        Vector128<sbyte> maskAC = Vector128.Create(0x0FC0FC00).AsSByte();
        Vector128<sbyte> maskBB = Vector128.Create(0x003F03F0).AsSByte();
        Vector128<ushort> shiftAC = Vector128.Create(0x04000040).AsUInt16();
        Vector128<short> shiftBB = Vector128.Create(0x01000010).AsInt16();

        Vector128<sbyte> lut = T.IsUrl
            ? Vector128.Create((sbyte)65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -17, 32, 0, 0)
            : Vector128.Create((sbyte)65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0);
        Vector128<sbyte> const51 = Vector128.Create((sbyte)51);
        Vector128<sbyte> const25 = Vector128.Create((sbyte)25);

        str = Ssse3.Shuffle(str, shuffleVec);

        Vector128<sbyte> t0 = Sse2.And(str, maskAC);
        Vector128<sbyte> t2 = Sse2.And(str, maskBB);
        Vector128<ushort> t1 = Sse2.MultiplyHigh(t0.AsUInt16(), shiftAC);
        Vector128<short> t3 = Sse2.MultiplyLow(t2.AsInt16(), shiftBB);
        str = Sse2.Or(t1.AsSByte(), t3.AsSByte());

        Vector128<byte> indices = Sse2.SubtractSaturate(str.AsByte(), const51.AsByte());
        Vector128<sbyte> mask = Sse2.CompareGreaterThan(str, const25);
        Vector128<sbyte> lutIdx = Sse2.Subtract(indices.AsSByte(), mask);
        return Sse2.Add(str, Ssse3.Shuffle(lut, lutIdx));
    }

    // ------------------------------------------------------------------
    // Encode core: bytes -> UTF-8 bytes
    // ------------------------------------------------------------------

    internal static void EncodeBytes<T>(byte* srcStart, int srcLength, byte* destStart)
        where T : struct, IAlphabet
    {
        byte* src = srcStart;
        byte* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 24 bytes -> 32 chars per loop ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;

            // The first block cannot read at src-4, so load 32 bytes at src and
            // realign with a 4-byte lane rotation (permutevar8x32).
            Vector256<int> permute = Vector256.Create(0, 0, 1, 2, 3, 4, 5, 6);
            Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
            str = Avx2.PermuteVar8x32(str.AsInt32(), permute).AsSByte();

            while (true)
            {
                Avx.Store((sbyte*)dest, EncodeVector256<T>(str));
                src += 24;
                dest += 32;
                if (src > srcMax)
                {
                    break;
                }

                // Subsequent blocks: overlapping load at src-4 puts the 12
                // payload bytes of each 128-bit lane where the shuffle expects.
                str = Avx.LoadVector256(src - 4).AsSByte();
            }
        }

        // ---- SSSE3: 12 bytes -> 16 chars per loop ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            do
            {
                Vector128<sbyte> str = Sse2.LoadVector128(src).AsSByte();
                Sse2.Store((sbyte*)dest, EncodeVector128<T>(str));
                src += 12;
                dest += 16;
            }
            while (src <= srcMax);
        }

        // ---- Scalar tail ----
        ref byte map = ref MemoryMarshal.GetReference(T.IsUrl ? UrlEncodingMap : EncodingMap);
        while (srcEnd - src >= 3)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8 | src[2]);
            dest[0] = Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            dest[3] = Unsafe.Add(ref map, (nint)(t & 0x3F));
            src += 3;
            dest += 4;
        }

        long remaining = srcEnd - src; // 0, 1 or 2
        if (remaining == 1)
        {
            uint t = (uint)(src[0] << 16);
            dest[0] = Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            if (!T.IsUrl)
            {
                dest[2] = (byte)'=';
                dest[3] = (byte)'=';
            }
        }
        else if (remaining == 2)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8);
            dest[0] = Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            if (!T.IsUrl)
            {
                dest[3] = (byte)'=';
            }
        }
    }

    // ------------------------------------------------------------------
    // Encode core: bytes -> UTF-16 chars
    //   (widen the ASCII vector directly with vpmovzxbw / punpcklbw)
    // ------------------------------------------------------------------

    internal static void EncodeChars<T>(byte* srcStart, int srcLength, char* destStart)
        where T : struct, IAlphabet
    {
        byte* src = srcStart;
        char* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 24 bytes -> 32 chars (two 32-byte stores) per loop ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;

            Vector256<int> permute = Vector256.Create(0, 0, 1, 2, 3, 4, 5, 6);
            Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
            str = Avx2.PermuteVar8x32(str.AsInt32(), permute).AsSByte();

            while (true)
            {
                Vector256<sbyte> ascii = EncodeVector256<T>(str);
                Avx.Store((short*)dest, Avx2.ConvertToVector256Int16(ascii.GetLower().AsByte()));
                Avx.Store((short*)(dest + 16), Avx2.ConvertToVector256Int16(ascii.GetUpper().AsByte()));
                src += 24;
                dest += 32;
                if (src > srcMax)
                {
                    break;
                }

                str = Avx.LoadVector256(src - 4).AsSByte();
            }
        }

        // ---- SSSE3: 12 bytes -> 16 chars per loop ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            Vector128<byte> zero = Vector128<byte>.Zero;
            do
            {
                Vector128<byte> ascii = EncodeVector128<T>(Sse2.LoadVector128(src).AsSByte()).AsByte();
                Sse2.Store((byte*)dest, Sse2.UnpackLow(ascii, zero));
                Sse2.Store((byte*)(dest + 8), Sse2.UnpackHigh(ascii, zero));
                src += 12;
                dest += 16;
            }
            while (src <= srcMax);
        }

        // ---- Scalar tail ----
        ref byte map = ref MemoryMarshal.GetReference(T.IsUrl ? UrlEncodingMap : EncodingMap);
        while (srcEnd - src >= 3)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8 | src[2]);
            dest[0] = (char)Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = (char)Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = (char)Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            dest[3] = (char)Unsafe.Add(ref map, (nint)(t & 0x3F));
            src += 3;
            dest += 4;
        }

        long remaining = srcEnd - src;
        if (remaining == 1)
        {
            uint t = (uint)(src[0] << 16);
            dest[0] = (char)Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = (char)Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            if (!T.IsUrl)
            {
                dest[2] = '=';
                dest[3] = '=';
            }
        }
        else if (remaining == 2)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8);
            dest[0] = (char)Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = (char)Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = (char)Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            if (!T.IsUrl)
            {
                dest[3] = '=';
            }
        }
    }

    // ------------------------------------------------------------------
    // Decode core: shared SIMD transform
    //
    //   pshufb LUTs indexed by the high/low nibble produce bitmasks whose
    //   AND is non-zero for any invalid character (verified in bulk with
    //   ptest). Valid characters are mapped to their 6-bit values with a
    //   delta LUT, then packed 4 -> 3 bytes with pmaddubsw + pmaddwd + pshufb.
    //
    //   Standard: '/' (0x2F) shares its high nibble with '+', so its delta is
    //   selected by adding cmpeq(str,0x2F) to the LUT index (Muła's trick).
    //   Url: '_' (0x5F) shares its high nibble with 'P'..'Z', so its delta is
    //   selected with a byte blend on cmpeq(str,0x5F) instead.
    // ------------------------------------------------------------------

    /// <summary>Decodes 32 chars into 24 bytes; false if any char is invalid.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool DecodeVector256<T>(Vector256<sbyte> str, out Vector256<sbyte> result)
        where T : struct, IAlphabet
    {
        Vector256<sbyte> lutHi = T.IsUrl
            ? Vector256.Create(
                (sbyte)0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x20,
                0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x20,
                0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10)
            : Vector256.Create(
                (sbyte)0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
                0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
                0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10);
        Vector256<sbyte> lutLo = T.IsUrl
            ? Vector256.Create(
                (sbyte)0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x13, 0x3B, 0x3B, 0x3A, 0x3B, 0x33,
                0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x13, 0x3B, 0x3B, 0x3A, 0x3B, 0x33)
            : Vector256.Create(
                (sbyte)0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A,
                0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A);
        Vector256<sbyte> lutShift = T.IsUrl
            ? Vector256.Create(
                (sbyte)0, 0, 17, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 17, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0)
            : Vector256.Create(
                (sbyte)0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0);
        Vector256<sbyte> mask2F = Vector256.Create((sbyte)0x2F);
        Vector256<sbyte> mergeConst0 = Vector256.Create(0x01400140).AsSByte();
        Vector256<short> mergeConst1 = Vector256.Create(0x00011000).AsInt16();
        Vector256<sbyte> packBytesInLaneMask = Vector256.Create(
            (sbyte)2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
            2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);
        Vector256<int> packLanesControl = Vector256.Create(0, 1, 2, 4, 5, 6, -1, -1);

        // pshufb only reads bits 0-3 (and bit 7) of each index, so masking the
        // shifted value with 0x2F instead of 0x0F is harmless and saves a constant.
        Vector256<sbyte> hiNibbles = Avx2.And(Avx2.ShiftRightLogical(str.AsInt32(), 4).AsSByte(), mask2F);
        Vector256<sbyte> loNibbles = Avx2.And(str, mask2F);
        Vector256<sbyte> hi = Avx2.Shuffle(lutHi, hiNibbles);
        Vector256<sbyte> lo = Avx2.Shuffle(lutLo, loNibbles);

        if (!Avx.TestZ(lo, hi))
        {
            result = default;
            return false; // contains an invalid character
        }

        Vector256<sbyte> shift;
        if (T.IsUrl)
        {
            Vector256<sbyte> eq5F = Avx2.CompareEqual(str, Vector256.Create((sbyte)0x5F));
            shift = Avx2.Shuffle(lutShift, hiNibbles);
            shift = Avx2.BlendVariable(shift, Vector256.Create((sbyte)-32), eq5F); // '_' -> 63
        }
        else
        {
            Vector256<sbyte> eq2F = Avx2.CompareEqual(str, mask2F);
            shift = Avx2.Shuffle(lutShift, Avx2.Add(eq2F, hiNibbles)); // '/' -> 63
        }

        str = Avx2.Add(str, shift); // every byte = 6-bit value

        // (a,b),(c,d) -> (a<<6|b),(c<<6|d) -> a<<18|b<<12|c<<6|d, then pack the
        // low 3 bytes of each dword.
        Vector256<short> mergeAbBc = Avx2.MultiplyAddAdjacent(str.AsByte(), mergeConst0);
        Vector256<int> merged = Avx2.MultiplyAddAdjacent(mergeAbBc, mergeConst1);
        Vector256<sbyte> packed = Avx2.Shuffle(merged.AsSByte(), packBytesInLaneMask);
        result = Avx2.PermuteVar8x32(packed.AsInt32(), packLanesControl).AsSByte();
        return true;
    }

    /// <summary>Decodes 16 chars into 12 bytes; false if any char is invalid.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool DecodeVector128<T>(Vector128<sbyte> str, out Vector128<sbyte> result)
        where T : struct, IAlphabet
    {
        Vector128<sbyte> lutHi = T.IsUrl
            ? Vector128.Create(
                (sbyte)0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x20,
                0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10)
            : Vector128.Create(
                (sbyte)0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
                0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10);
        Vector128<sbyte> lutLo = T.IsUrl
            ? Vector128.Create(
                (sbyte)0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x13, 0x3B, 0x3B, 0x3A, 0x3B, 0x33)
            : Vector128.Create(
                (sbyte)0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A);
        Vector128<sbyte> lutShift = T.IsUrl
            ? Vector128.Create((sbyte)0, 0, 17, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0)
            : Vector128.Create((sbyte)0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0);
        Vector128<sbyte> mask2F = Vector128.Create((sbyte)0x2F);
        Vector128<sbyte> mergeConst0 = Vector128.Create(0x01400140).AsSByte();
        Vector128<short> mergeConst1 = Vector128.Create(0x00011000).AsInt16();
        Vector128<sbyte> packBytesMask = Vector128.Create(
            (sbyte)2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);

        Vector128<sbyte> hiNibbles = Sse2.And(Sse2.ShiftRightLogical(str.AsInt32(), 4).AsSByte(), mask2F);
        Vector128<sbyte> loNibbles = Sse2.And(str, mask2F);
        Vector128<sbyte> hi = Ssse3.Shuffle(lutHi, hiNibbles);
        Vector128<sbyte> lo = Ssse3.Shuffle(lutLo, loNibbles);

        // Validation: one ptest on SSE4.1, otherwise SSE2 pmovmskb fallback.
        if (Sse41.IsSupported)
        {
            if (!Sse41.TestZ(lo, hi))
            {
                result = default;
                return false;
            }
        }
        else
        {
            Vector128<sbyte> and = Sse2.And(lo, hi);
            if (Sse2.MoveMask(Sse2.CompareEqual(and, Vector128<sbyte>.Zero)) != 0xFFFF)
            {
                result = default;
                return false;
            }
        }

        Vector128<sbyte> shift;
        if (T.IsUrl)
        {
            Vector128<sbyte> eq5F = Sse2.CompareEqual(str, Vector128.Create((sbyte)0x5F));
            Vector128<sbyte> neg32 = Vector128.Create((sbyte)-32);
            shift = Ssse3.Shuffle(lutShift, hiNibbles);
            shift = Sse41.IsSupported
                ? Sse41.BlendVariable(shift, neg32, eq5F)
                : Sse2.Or(Sse2.And(eq5F, neg32), Sse2.AndNot(eq5F, shift)); // '_' -> 63
        }
        else
        {
            Vector128<sbyte> eq2F = Sse2.CompareEqual(str, mask2F);
            shift = Ssse3.Shuffle(lutShift, Sse2.Add(eq2F, hiNibbles)); // '/' -> 63
        }

        str = Sse2.Add(str, shift);

        Vector128<short> mergeAbBc = Ssse3.MultiplyAddAdjacent(str.AsByte(), mergeConst0);
        Vector128<int> merged = Sse2.MultiplyAddAdjacent(mergeAbBc, mergeConst1);
        result = Ssse3.Shuffle(merged.AsSByte(), packBytesMask);
        return true;
    }

    // ------------------------------------------------------------------
    // Decode core: UTF-8 bytes -> bytes
    //   srcLength is the length with padding already trimmed. destEnd is the
    //   end of the destination buffer (guards the over-length SIMD stores).
    // ------------------------------------------------------------------
    internal static bool DecodeUtf8<T>(byte* srcStart, int srcLength, byte* destStart, byte* destEnd)
        where T : struct, IAlphabet
    {
        byte* src = srcStart;
        byte* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 32 chars -> 24 bytes per loop (32-byte store, 24 valid) ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;
            while (src <= srcMax && dest + 32 <= destEnd)
            {
                Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
                if (!DecodeVector256<T>(str, out Vector256<sbyte> decoded))
                {
                    break; // let the scalar tail pinpoint the invalid character
                }

                Avx.Store((sbyte*)dest, decoded);
                src += 32;
                dest += 24;
            }
        }

        // ---- SSSE3: 16 chars -> 12 bytes per loop (16-byte store, 12 valid) ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            while (src <= srcMax && dest + 16 <= destEnd)
            {
                Vector128<sbyte> str = Sse2.LoadVector128(src).AsSByte();
                if (!DecodeVector128<T>(str, out Vector128<sbyte> decoded))
                {
                    break;
                }

                Sse2.Store((sbyte*)dest, decoded);
                src += 16;
                dest += 12;
            }
        }

        // ---- Scalar: 4 chars -> 3 bytes ----
        ref sbyte map = ref MemoryMarshal.GetReference(T.IsUrl ? UrlDecodingMap : DecodingMap);
        while (srcEnd - src >= 4)
        {
            int i0 = Unsafe.Add(ref map, (nint)src[0]);
            int i1 = Unsafe.Add(ref map, (nint)src[1]);
            int i2 = Unsafe.Add(ref map, (nint)src[2]);
            int i3 = Unsafe.Add(ref map, (nint)src[3]);
            if ((i0 | i1 | i2 | i3) < 0)
            {
                return false;
            }

            uint t = (uint)(i0 << 18 | i1 << 12 | i2 << 6 | i3);
            dest[0] = (byte)(t >> 16);
            dest[1] = (byte)(t >> 8);
            dest[2] = (byte)t;
            src += 4;
            dest += 3;
        }

        // ---- Remainder (0, 2 or 3 chars) ----
        long rem = srcEnd - src;
        if (rem == 2)
        {
            int i0 = Unsafe.Add(ref map, (nint)src[0]);
            int i1 = Unsafe.Add(ref map, (nint)src[1]);
            if ((i0 | i1) < 0)
            {
                return false;
            }

            dest[0] = (byte)(i0 << 2 | i1 >> 4);
        }
        else if (rem == 3)
        {
            int i0 = Unsafe.Add(ref map, (nint)src[0]);
            int i1 = Unsafe.Add(ref map, (nint)src[1]);
            int i2 = Unsafe.Add(ref map, (nint)src[2]);
            if ((i0 | i1 | i2) < 0)
            {
                return false;
            }

            dest[0] = (byte)(i0 << 2 | i1 >> 4);
            dest[1] = (byte)(i1 << 4 | i2 >> 2);
        }

        return true;
    }

    // ------------------------------------------------------------------
    // Decode core: UTF-16 chars -> bytes
    //   Chars are narrowed with packus (saturating). Non-ASCII characters
    //   saturate to 0 or 255, which the LUT validation always rejects.
    // ------------------------------------------------------------------

    internal static bool DecodeChars<T>(char* srcStart, int srcLength, byte* destStart, byte* destEnd)
        where T : struct, IAlphabet
    {
        char* src = srcStart;
        byte* dest = destStart;
        char* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 32 chars (two 32-byte loads) -> 24 bytes per loop ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            char* srcMax = srcEnd - 32;
            while (src <= srcMax && dest + 32 <= destEnd)
            {
                Vector256<short> c0 = Avx.LoadVector256((short*)src);
                Vector256<short> c1 = Avx.LoadVector256((short*)(src + 16));
                Vector256<byte> packed = Avx2.PackUnsignedSaturate(c0, c1);
                // packus interleaves 128-bit lanes; restore order per 64 bits.
                Vector256<sbyte> str = Avx2.Permute4x64(packed.AsInt64(), 0b_11_01_10_00).AsSByte();
                if (!DecodeVector256<T>(str, out Vector256<sbyte> decoded))
                {
                    break;
                }

                Avx.Store((sbyte*)dest, decoded);
                src += 32;
                dest += 24;
            }
        }

        // ---- SSSE3: 16 chars -> 12 bytes per loop ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            char* srcMax = srcEnd - 16;
            while (src <= srcMax && dest + 16 <= destEnd)
            {
                Vector128<short> c0 = Sse2.LoadVector128((short*)src);
                Vector128<short> c1 = Sse2.LoadVector128((short*)(src + 8));
                Vector128<sbyte> str = Sse2.PackUnsignedSaturate(c0, c1).AsSByte();
                if (!DecodeVector128<T>(str, out Vector128<sbyte> decoded))
                {
                    break;
                }

                Sse2.Store((sbyte*)dest, decoded);
                src += 16;
                dest += 12;
            }
        }

        // ---- Scalar ----
        ref sbyte map = ref MemoryMarshal.GetReference(T.IsUrl ? UrlDecodingMap : DecodingMap);
        while (srcEnd - src >= 4)
        {
            uint c0 = src[0], c1 = src[1], c2 = src[2], c3 = src[3];
            if ((c0 | c1 | c2 | c3) > 0xFF)
            {
                return false;
            }

            int i0 = Unsafe.Add(ref map, (nint)c0);
            int i1 = Unsafe.Add(ref map, (nint)c1);
            int i2 = Unsafe.Add(ref map, (nint)c2);
            int i3 = Unsafe.Add(ref map, (nint)c3);
            if ((i0 | i1 | i2 | i3) < 0)
            {
                return false;
            }

            uint t = (uint)(i0 << 18 | i1 << 12 | i2 << 6 | i3);
            dest[0] = (byte)(t >> 16);
            dest[1] = (byte)(t >> 8);
            dest[2] = (byte)t;
            src += 4;
            dest += 3;
        }

        long rem = srcEnd - src;
        if (rem == 2)
        {
            uint c0 = src[0], c1 = src[1];
            if ((c0 | c1) > 0xFF)
            {
                return false;
            }

            int i0 = Unsafe.Add(ref map, (nint)c0);
            int i1 = Unsafe.Add(ref map, (nint)c1);
            if ((i0 | i1) < 0)
            {
                return false;
            }

            dest[0] = (byte)(i0 << 2 | i1 >> 4);
        }
        else if (rem == 3)
        {
            uint c0 = src[0], c1 = src[1], c2 = src[2];
            if ((c0 | c1 | c2) > 0xFF)
            {
                return false;
            }

            int i0 = Unsafe.Add(ref map, (nint)c0);
            int i1 = Unsafe.Add(ref map, (nint)c1);
            int i2 = Unsafe.Add(ref map, (nint)c2);
            if ((i0 | i1 | i2) < 0)
            {
                return false;
            }

            dest[0] = (byte)(i0 << 2 | i1 >> 4);
            dest[1] = (byte)(i1 << 4 | i2 >> 2);
        }

        return true;
    }
}
