// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Arc.Crypto;

#pragma warning disable SA1117
#pragma warning disable SA1519 // Braces should not be omitted from multi-line child statement

public static unsafe class FastBase64
{
    // ------------------------------------------------------------------
    // Length calculation
    // ------------------------------------------------------------------

    /// <summary>
    /// Gets the exact number of Base64 characters required to encode the specified number of bytes,
    /// including padding characters.
    /// </summary>
    /// <param name="byteCount">The number of bytes to encode.</param>
    /// <returns>The exact number of Base64 characters required.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="byteCount"/> is negative, or the encoded length exceeds <see cref="int.MaxValue"/>.
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
    /// Gets the maximum number of decoded bytes for a Base64 sequence of the specified length.
    /// This value can be used as a safe destination buffer size regardless of padding.
    /// </summary>
    /// <param name="encodedLength">The length of the Base64-encoded sequence.</param>
    /// <returns>The maximum number of decoded bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="encodedLength"/> is negative.
    /// </exception>
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
    /// Gets the exact number of bytes produced by decoding the specified UTF-8 Base64 sequence.
    /// Trailing padding characters are taken into account.
    /// </summary>
    /// <param name="utf8">The Base64 sequence represented as UTF-8 (ASCII) bytes.</param>
    /// <returns>The exact number of decoded bytes.</returns>
    /// <exception cref="FormatException">
    /// The Base64 sequence has an invalid length.
    /// </exception>
    public static int GetDecodedLength(ReadOnlySpan<byte> utf8)
    {
        int len = TrimPadding(utf8, out _);
        return DecodedLengthFromTrimmed(len);
    }

    /// <summary>
    /// Gets the exact number of bytes produced by decoding the specified Base64 character sequence.
    /// Trailing padding characters are taken into account.
    /// </summary>
    /// <param name="chars">The Base64 character sequence.</param>  
    /// <returns>The exact number of decoded bytes.</returns>
    /// <exception cref="FormatException">
    /// The Base64 sequence has an invalid length.
    /// </exception>
    public static int GetDecodedLength(ReadOnlySpan<char> chars)
    {
        int len = TrimPadding(chars, out _);
        return DecodedLengthFromTrimmed(len);
    }

    // ------------------------------------------------------------------
    // Encoding (public API)
    // ------------------------------------------------------------------

    /// <summary>
    /// Encodes the specified bytes as Base64 into a UTF-8 (ASCII) byte destination.
    /// </summary>
    /// <param name="bytes">The bytes to encode.</param>
    /// <param name="utf8Destination">The destination buffer that receives the Base64 UTF-8 bytes.</param>
    /// <returns>The number of bytes written to <paramref name="utf8Destination"/>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="utf8Destination"/> is too small to contain the encoded data.
    /// </exception>
    public static int Encode(ReadOnlySpan<byte> bytes, Span<byte> utf8Destination)
    {
        int encodedLength = GetEncodedLength(bytes.Length);
        if (utf8Destination.Length < encodedLength)
        {
            throw new ArgumentException("Destination is too small.", nameof(utf8Destination));
        }

        if (bytes.IsEmpty)
        {
            return 0;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        fixed (byte* dest = &MemoryMarshal.GetReference(utf8Destination))
        {
            EncodeBytesCore(src, bytes.Length, dest);
        }

        return encodedLength;
    }

    /// <summary>
    /// Encodes the specified bytes as Base64 into a UTF-16 character destination.
    /// </summary>
    /// <param name="bytes">The bytes to encode.</param>
    /// <param name="charsDestination">The destination buffer that receives the Base64 characters.</param>
    /// <returns>The number of characters written to <paramref name="charsDestination"/>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="charsDestination"/> is too small to contain the encoded data.
    /// </exception>
    public static int Encode(ReadOnlySpan<byte> bytes, Span<char> charsDestination)
    {
        int encodedLength = GetEncodedLength(bytes.Length);
        if (charsDestination.Length < encodedLength)
        {
            throw new ArgumentException("Destination is too small.", nameof(charsDestination));
        }

        if (bytes.IsEmpty)
        {
            return 0;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        fixed (char* dest = &MemoryMarshal.GetReference(charsDestination))
        {
            EncodeCharsCore(src, bytes.Length, dest);
        }

        return encodedLength;
    }

    /// <summary>
    /// Encodes the specified bytes as Base64 and returns the result as a string.
    /// </summary>
    /// <param name="bytes">The bytes to encode.</param>
    /// <returns>A Base64 string representing the input bytes.</returns>
    public static string EncodeToString(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return string.Empty;
        }

        int encodedLength = GetEncodedLength(bytes.Length);

        // Write directly into the newly allocated string through a fixed pointer.
        // This follows the same general pattern as string.Create and is safe because
        // the string has just been allocated and is not yet referenced elsewhere.
        string result = new string('\0', encodedLength);
        fixed (char* dest = result)
        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        {
            EncodeCharsCore(src, bytes.Length, dest);
        }

        return result;
    }

    // ------------------------------------------------------------------
    // Decoding (public API)
    // ------------------------------------------------------------------

    /// <summary>
    /// Attempts to decode a UTF-8 (ASCII) Base64 sequence into the specified byte destination.
    /// </summary>
    /// <param name="utf8">The Base64 sequence represented as UTF-8 (ASCII) bytes.</param>
    /// <param name="bytesDestination">The destination buffer that receives the decoded bytes.</param>
    /// <param name="bytesWritten">
    /// When this method returns, contains the number of bytes written to
    /// <paramref name="bytesDestination"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if decoding succeeds; otherwise, <see langword="false"/>
    /// if the input is invalid or the destination buffer is too small.
    /// </returns>
    public static bool TryDecode(ReadOnlySpan<byte> utf8, Span<byte> bytesDestination, out int bytesWritten)
    {
        bytesWritten = 0;
        int len = TrimPadding(utf8, out bool ok);
        if (!ok)
        {
            return false;
        }

        int required = DecodedLengthFromTrimmedNoThrow(len);
        if (required < 0 || bytesDestination.Length < required)
        {
            return false;
        }

        if (len == 0)
        {
            return true;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(utf8))
        fixed (byte* dest = &MemoryMarshal.GetReference(bytesDestination))
        {
            if (!DecodeFromUtf8Core(src, len, dest, dest + bytesDestination.Length))
            {
                return false;
            }
        }

        bytesWritten = required;
        return true;
    }

    /// <summary>
    /// Attempts to decode a UTF-16 Base64 character sequence into the specified byte destination.
    /// </summary>
    /// <param name="chars">The Base64 character sequence.</param>
    /// <param name="bytesDestination">The destination buffer that receives the decoded bytes.</param>
    /// <param name="bytesWritten">
    /// When this method returns, contains the number of bytes written to
    /// <paramref name="bytesDestination"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if decoding succeeds; otherwise, <see langword="false"/>
    /// if the input is invalid or the destination buffer is too small.
    /// </returns>
    public static bool TryDecode(ReadOnlySpan<char> chars, Span<byte> bytesDestination, out int bytesWritten)
    {
        bytesWritten = 0;
        int len = TrimPadding(chars, out bool ok);
        if (!ok)
        {
            return false;
        }

        int required = DecodedLengthFromTrimmedNoThrow(len);
        if (required < 0 || bytesDestination.Length < required)
        {
            return false;
        }

        if (len == 0)
        {
            return true;
        }

        fixed (char* src = &MemoryMarshal.GetReference(chars))
        fixed (byte* dest = &MemoryMarshal.GetReference(bytesDestination))
        {
            if (!DecodeFromCharsCore(src, len, dest, dest + bytesDestination.Length))
            {
                return false;
            }
        }

        bytesWritten = required;
        return true;
    }

    /// <summary>
    /// Decodes a UTF-8 (ASCII) Base64 sequence into the specified byte destination.
    /// </summary>
    /// <param name="utf8">The Base64 sequence represented as UTF-8 (ASCII) bytes.</param>
    /// <param name="bytesDestination">The destination buffer that receives the decoded bytes.</param>
    /// <returns>The number of bytes written to <paramref name="bytesDestination"/>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="bytesDestination"/> may be too small to contain the decoded data.
    /// </exception>
    /// <exception cref="FormatException">
    /// The input is not a valid Base64 sequence.
    /// </exception>
    public static int Decode(ReadOnlySpan<byte> utf8, Span<byte> bytesDestination)
    {
        if (!TryDecode(utf8, bytesDestination, out int written))
        {
            ThrowInvalidBase64(bytesDestination.Length, utf8.Length);
        }

        return written;
    }

    /// <summary>
    /// Decodes a UTF-16 Base64 character sequence into the specified byte destination.
    /// </summary>
    /// <param name="chars">The Base64 character sequence.</param>
    /// <param name="bytesDestination">The destination buffer that receives the decoded bytes.</param>
    /// <returns>The number of bytes written to <paramref name="bytesDestination"/>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="bytesDestination"/> may be too small to contain the decoded data.
    /// </exception>
    /// <exception cref="FormatException">
    /// The input is not a valid Base64 sequence.
    /// </exception>
    public static int Decode(ReadOnlySpan<char> chars, Span<byte> bytesDestination)
    {
        if (!TryDecode(chars, bytesDestination, out int written))
        {
            ThrowInvalidBase64(bytesDestination.Length, chars.Length);
        }

        return written;
    }

    /// <summary>
    /// Decodes the specified Base64 string and returns the decoded bytes in a new array.
    /// </summary>
    /// <param name="base64">The Base64 string to decode.</param>
    /// <returns>A byte array containing the decoded data.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="base64"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">
    /// <paramref name="base64"/> is not a valid Base64 string.
    /// </exception>
    public static byte[] Decode(string base64)
    {
        ArgumentNullException.ThrowIfNull(base64);
        ReadOnlySpan<char> chars = base64;
        int required = GetDecodedLength(chars); // Throws FormatException here if the length is invalid.
        if (required == 0)
        {
            return Array.Empty<byte>();
        }

        byte[] result = new byte[required];
        if (!TryDecode(chars, result, out _))
        {
            throw new FormatException("The input is not a valid Base64 string.");
        }

        return result;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInvalidBase64(int destLength, int srcLength)
    {
        if (destLength < GetMaxDecodedLength(srcLength))
        {
            throw new ArgumentException("Destination may be too small.", "bytesDestination");
        }

        throw new FormatException("The input is not a valid Base64 sequence.");
    }

    // ------------------------------------------------------------------
    // Length and padding helpers
    // ------------------------------------------------------------------

    // Returns the length excluding up to two trailing '=' padding characters.
    // Sets ok to false if the padding layout is invalid.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int TrimPadding(ReadOnlySpan<byte> s, out bool ok)
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

        // When padding is present, the total encoded length must be a multiple of four.
        ok = trimmed == len || (len & 3) == 0;
        return trimmed;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int TrimPadding(ReadOnlySpan<char> s, out bool ok)
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

    // Converts the length after removing padding to the exact decoded byte count.
    // A length where length % 4 == 1 is invalid and returns -1.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DecodedLengthFromTrimmedNoThrow(int trimmedLength)
    {
        int rem = trimmedLength & 3;
        if (rem == 1)
        {
            return -1;
        }

        return ((trimmedLength >> 2) * 3) + (rem == 0 ? 0 : rem - 1);
    }

    private static int DecodedLengthFromTrimmed(int trimmedLength)
    {
        int r = DecodedLengthFromTrimmedNoThrow(trimmedLength);
        if (r < 0)
        {
            throw new FormatException("Invalid Base64 length.");
        }

        return r;
    }

    // ------------------------------------------------------------------
    // Conversion tables
    // ------------------------------------------------------------------

    private static ReadOnlySpan<byte> EncodingMap =>
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"u8;

    // ASCII to 6-bit value. Invalid characters map to -1.
    // The table is embedded as static RVA data and does not allocate.
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

    // ------------------------------------------------------------------
    // Encoding core: common SIMD transformation
    //
    // For each 32-bit lane of the input vector, the three source bytes are
    // arranged as [b1, b0, b2, b1] in little-endian order. AND operations
    // and multiply-shifts then split them into four 6-bit indices, which are
    // converted to ASCII using saturated subtraction and a pshufb lookup table
    // (Muła's technique).
    // ------------------------------------------------------------------

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<sbyte> EncodeVector256(Vector256<sbyte> str)
    {
        // Shuffle mask that arranges three input bytes as [b1,b0,b2,b1] in each lane.
        Vector256<sbyte> shuffleVec = Vector256.Create(
             5, 4, 6, 5, 8, 7, 9, 8, 11, 10, 12, 11, 14, 13, 15, 14,
             1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);

        Vector256<sbyte> maskAC = Vector256.Create(0x0FC0FC00).AsSByte();
        Vector256<sbyte> maskBB = Vector256.Create(0x003F03F0).AsSByte();
        Vector256<ushort> shiftAC = Vector256.Create(0x04000040).AsUInt16();
        Vector256<short> shiftBB = Vector256.Create(0x01000010).AsInt16();

        // 6-bit value to ASCII adjustment lookup table.
        Vector256<sbyte> lut = Vector256.Create(
            65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0,
            65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0);
        Vector256<sbyte> const51 = Vector256.Create((sbyte)51);
        Vector256<sbyte> const25 = Vector256.Create((sbyte)25);

        str = Avx2.Shuffle(str, shuffleVec);

        Vector256<sbyte> t0 = Avx2.And(str, maskAC);
        Vector256<sbyte> t2 = Avx2.And(str, maskBB);
        Vector256<ushort> t1 = Avx2.MultiplyHigh(t0.AsUInt16(), shiftAC);
        Vector256<short> t3 = Avx2.MultiplyLow(t2.AsInt16(), shiftBB);
        str = Avx2.Or(t1.AsSByte(), t3.AsSByte()); // Each byte is a 6-bit index in the range 0..63.

        // Convert indices: <=25 -> +'A', 26..51 -> +('a'-26),
        // 52..61 -> +('0'-52), 62 -> '+', 63 -> '/'.
        Vector256<byte> indices = Avx2.SubtractSaturate(str.AsByte(), const51.AsByte());
        Vector256<sbyte> mask = Avx2.CompareGreaterThan(str, const25);
        Vector256<sbyte> lutIdx = Avx2.Subtract(indices.AsSByte(), mask);
        return Avx2.Add(str, Avx2.Shuffle(lut, lutIdx));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<sbyte> EncodeVector128(Vector128<sbyte> str)
    {
        Vector128<sbyte> shuffleVec = Vector128.Create(
            (sbyte)1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);

        Vector128<sbyte> maskAC = Vector128.Create(0x0FC0FC00).AsSByte();
        Vector128<sbyte> maskBB = Vector128.Create(0x003F03F0).AsSByte();
        Vector128<ushort> shiftAC = Vector128.Create(0x04000040).AsUInt16();
        Vector128<short> shiftBB = Vector128.Create(0x01000010).AsInt16();

        Vector128<sbyte> lut = Vector128.Create(
            (sbyte)65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0);
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
    // Encoding core: bytes -> UTF-8 bytes
    // ------------------------------------------------------------------

    private static void EncodeBytesCore(byte* srcStart, int srcLength, byte* destStart)
    {
        byte* src = srcStart;
        byte* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 24 bytes -> 32 characters per iteration ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;

            // The first iteration cannot read from src - 4, so load 32 bytes from src
            // and align the data using a lane permutation equivalent to a logical
            // four-byte right shift.
            Vector256<int> permute = Vector256.Create(0, 0, 1, 2, 3, 4, 5, 6);
            Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
            str = Avx2.PermuteVar8x32(str.AsInt32(), permute).AsSByte();

            while (true)
            {
                Avx.Store((sbyte*)dest, EncodeVector256(str));
                src += 24;
                dest += 32;
                if (src > srcMax)
                {
                    break;
                }

                // From the second iteration onward, load from src - 4 so that
                // the lower lane overlaps the preceding input by four bytes.
                str = Avx.LoadVector256(src - 4).AsSByte();
            }
        }

        // ---- SSSE3: 12 bytes -> 16 characters per iteration ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            do
            {
                Vector128<sbyte> str = Sse2.LoadVector128(src).AsSByte();
                Sse2.Store((sbyte*)dest, EncodeVector128(str));
                src += 12;
                dest += 16;
            }
            while (src <= srcMax);
        }

        // ---- Scalar ----
        ref byte map = ref MemoryMarshal.GetReference(EncodingMap);
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

        long remaining = srcEnd - src; // 0, 1, or 2 bytes.
        if (remaining == 1)
        {
            uint t = (uint)(src[0] << 16);
            dest[0] = Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = (byte)'=';
            dest[3] = (byte)'=';
        }
        else if (remaining == 2)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8);
            dest[0] = Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            dest[3] = (byte)'=';
        }
    }

    // ------------------------------------------------------------------
    // Encoding core: bytes -> UTF-16 chars
    //   Zero-extends ASCII vectors using vpmovzxbw / punpcklbw and stores
    //   them directly as UTF-16 characters.
    // ------------------------------------------------------------------

    private static void EncodeCharsCore(byte* srcStart, int srcLength, char* destStart)
    {
        byte* src = srcStart;
        char* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 24 bytes -> 32 characters (64-byte store) per iteration ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;

            Vector256<int> permute = Vector256.Create(0, 0, 1, 2, 3, 4, 5, 6);
            Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
            str = Avx2.PermuteVar8x32(str.AsInt32(), permute).AsSByte();

            while (true)
            {
                Vector256<sbyte> ascii = EncodeVector256(str);
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

        // ---- SSSE3: 12 bytes -> 16 characters per iteration ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            Vector128<byte> zero = Vector128<byte>.Zero;
            do
            {
                Vector128<byte> ascii = EncodeVector128(Sse2.LoadVector128(src).AsSByte()).AsByte();
                Sse2.Store((byte*)dest, Sse2.UnpackLow(ascii, zero));
                Sse2.Store((byte*)(dest + 8), Sse2.UnpackHigh(ascii, zero));
                src += 12;
                dest += 16;
            }
            while (src <= srcMax);
        }

        // ---- Scalar ----
        ref byte map = ref MemoryMarshal.GetReference(EncodingMap);
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
            dest[2] = '=';
            dest[3] = '=';
        }
        else if (remaining == 2)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8);
            dest[0] = (char)Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = (char)Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = (char)Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            dest[3] = '=';
        }
    }

    // ------------------------------------------------------------------
    // Decoding core: common SIMD transformation
    //
    // Uses pshufb lookup tables indexed by the high and low nibbles to
    // derive validation bitmasks. A nonzero AND result indicates an invalid
    // character and is checked collectively with ptest. Valid characters
    // are converted to 6-bit values using an adjustment lookup table, then
    // packed into three-byte groups using pmaddubsw, pmaddwd, and pshufb.
    // ------------------------------------------------------------------

    /// <summary>
    /// Decodes 32 Base64 characters into 24 bytes.
    /// </summary>
    /// <param name="str">The vector containing 32 Base64 characters.</param>
    /// <param name="result">
    /// When successful, receives the decoded bytes. The result is undefined if invalid characters are present.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if all characters are valid Base64 characters;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool DecodeVector256(Vector256<sbyte> str, out Vector256<sbyte> result)
    {
        Vector256<sbyte> lutHi = Vector256.Create(
            0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10).AsSByte();
        Vector256<sbyte> lutLo = Vector256.Create(
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A,
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A).AsSByte();
        Vector256<sbyte> lutShift = Vector256.Create(
            (sbyte)0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0);
        Vector256<sbyte> mask2F = Vector256.Create((sbyte)0x2F);
        Vector256<sbyte> mergeConst0 = Vector256.Create(0x01400140).AsSByte();
        Vector256<short> mergeConst1 = Vector256.Create(0x00011000).AsInt16();
        Vector256<sbyte> packBytesInLaneMask = Vector256.Create(
            (sbyte)2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
            2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);
        Vector256<int> packLanesControl = Vector256.Create(0, 1, 2, 4, 5, 6, -1, -1);

        Vector256<sbyte> hiNibbles = Avx2.And(Avx2.ShiftRightLogical(str.AsInt32(), 4).AsSByte(), mask2F);
        Vector256<sbyte> loNibbles = Avx2.And(str, mask2F);
        Vector256<sbyte> hi = Avx2.Shuffle(lutHi, hiNibbles);
        Vector256<sbyte> lo = Avx2.Shuffle(lutLo, loNibbles);

        if (!Avx.TestZ(lo, hi))
        {
            result = default;
            return false; // Contains an invalid character.
        }

        Vector256<sbyte> eq2F = Avx2.CompareEqual(str, mask2F);
        Vector256<sbyte> shift = Avx2.Shuffle(lutShift, Avx2.Add(eq2F, hiNibbles));
        str = Avx2.Add(str, shift); // Each byte is now a 6-bit value.

        // (a<<6|b), (c<<6|d) -> (a<<18|b<<12|c<<6|d), then pack the lower three bytes.
        Vector256<short> mergeAbBc = Avx2.MultiplyAddAdjacent(str.AsByte(), mergeConst0);
        Vector256<int> merged = Avx2.MultiplyAddAdjacent(mergeAbBc, mergeConst1);
        Vector256<sbyte> packed = Avx2.Shuffle(merged.AsSByte(), packBytesInLaneMask);
        result = Avx2.PermuteVar8x32(packed.AsInt32(), packLanesControl).AsSByte();
        return true;
    }

    /// <summary>
    /// Decodes 16 Base64 characters into 12 bytes.
    /// </summary>
    /// <param name="str">The vector containing 16 Base64 characters.</param>
    /// <param name="result">When successful, receives the decoded bytes.</param>
    /// <returns>
    /// <see langword="true"/> if all characters are valid Base64 characters;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool DecodeVector128(Vector128<sbyte> str, out Vector128<sbyte> result)
    {
        Vector128<sbyte> lutHi = Vector128.Create(
            0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10).AsSByte();
        Vector128<sbyte> lutLo = Vector128.Create(
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A).AsSByte();
        Vector128<sbyte> lutShift = Vector128.Create(
            (sbyte)0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0);
        Vector128<sbyte> mask2F = Vector128.Create((sbyte)0x2F);
        Vector128<sbyte> mergeConst0 = Vector128.Create(0x01400140).AsSByte();
        Vector128<short> mergeConst1 = Vector128.Create(0x00011000).AsInt16();
        Vector128<sbyte> packBytesMask = Vector128.Create(
            (sbyte)2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);

        Vector128<sbyte> hiNibbles = Sse2.And(Sse2.ShiftRightLogical(str.AsInt32(), 4).AsSByte(), mask2F);
        Vector128<sbyte> loNibbles = Sse2.And(str, mask2F);
        Vector128<sbyte> hi = Ssse3.Shuffle(lutHi, hiNibbles);
        Vector128<sbyte> lo = Ssse3.Shuffle(lutLo, loNibbles);

        // Validation uses the SSE4.1 ptest instruction when available;
        // otherwise, it falls back to SSE2 pmovmskb.
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

        Vector128<sbyte> eq2F = Sse2.CompareEqual(str, mask2F);
        Vector128<sbyte> shift = Ssse3.Shuffle(lutShift, Sse2.Add(eq2F, hiNibbles));
        str = Sse2.Add(str, shift);

        Vector128<short> mergeAbBc = Ssse3.MultiplyAddAdjacent(str.AsByte(), mergeConst0);
        Vector128<int> merged = Sse2.MultiplyAddAdjacent(mergeAbBc, mergeConst1);
        result = Ssse3.Shuffle(merged.AsSByte(), packBytesMask);
        return true;
    }

    // ------------------------------------------------------------------
    // Decoding core: UTF-8 bytes -> bytes
    //   srcLength is the length after removing padding. destEnd points to
    //   the end of the destination buffer and is used to prevent SIMD stores
    //   from writing beyond the buffer.
    // ------------------------------------------------------------------

    private static bool DecodeFromUtf8Core(byte* srcStart, int srcLength, byte* destStart, byte* destEnd)
    {
        byte* src = srcStart;
        byte* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 32 characters -> 24 bytes per iteration
        //      (32-byte store, 24 valid bytes) ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;
            while (src <= srcMax && dest + 32 <= destEnd)
            {
                Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
                if (!DecodeVector256(str, out Vector256<sbyte> decoded))
                {
                    break; // Let the scalar path detect invalid characters precisely.
                }

                Avx.Store((sbyte*)dest, decoded);
                src += 32;
                dest += 24;
            }
        }

        // ---- SSSE3: 16 characters -> 12 bytes per iteration
        //      (16-byte store, 12 valid bytes) ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            while (src <= srcMax && dest + 16 <= destEnd)
            {
                Vector128<sbyte> str = Sse2.LoadVector128(src).AsSByte();
                if (!DecodeVector128(str, out Vector128<sbyte> decoded))
                {
                    break;
                }

                Sse2.Store((sbyte*)dest, decoded);
                src += 16;
                dest += 12;
            }
        }

        // ---- Scalar: 4 characters -> 3 bytes ----
        ref sbyte map = ref MemoryMarshal.GetReference(DecodingMap);
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

        // ---- Remainder: 0, 2, or 3 characters ----
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
    // Decoding core: UTF-16 chars -> bytes
    //   Narrows chars to bytes using packus (saturating narrowing).
    //   Non-ASCII characters saturate to either 0 or 255 and are therefore
    //   guaranteed to be rejected by the lookup-table validation.
    // ------------------------------------------------------------------

    private static bool DecodeFromCharsCore(char* srcStart, int srcLength, byte* destStart, byte* destEnd)
    {
        char* src = srcStart;
        byte* dest = destStart;
        char* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 32 characters (two 64-byte loads) -> 24 bytes per iteration ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            char* srcMax = srcEnd - 32;
            while (src <= srcMax && dest + 32 <= destEnd)
            {
                Vector256<short> c0 = Avx.LoadVector256((short*)src);
                Vector256<short> c1 = Avx.LoadVector256((short*)(src + 16));
                Vector256<byte> packed = Avx2.PackUnsignedSaturate(c0, c1);

                // packus packs independently within each lane, so reorder
                // the result in 64-bit units to restore sequential character order.
                Vector256<sbyte> str = Avx2.Permute4x64(packed.AsInt64(), 0b_11_01_10_00).AsSByte();
                if (!DecodeVector256(str, out Vector256<sbyte> decoded))
                {
                    break;
                }

                Avx.Store((sbyte*)dest, decoded);
                src += 32;
                dest += 24;
            }
        }

        // ---- SSSE3: 16 characters -> 12 bytes per iteration ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            char* srcMax = srcEnd - 16;
            while (src <= srcMax && dest + 16 <= destEnd)
            {
                Vector128<short> c0 = Sse2.LoadVector128((short*)src);
                Vector128<short> c1 = Sse2.LoadVector128((short*)(src + 8));
                Vector128<sbyte> str = Sse2.PackUnsignedSaturate(c0, c1).AsSByte();
                if (!DecodeVector128(str, out Vector128<sbyte> decoded))
                {
                    break;
                }

                Sse2.Store((sbyte*)dest, decoded);
                src += 16;
                dest += 12;
            }
        }

        // ---- Scalar ----
        ref sbyte map = ref MemoryMarshal.GetReference(DecodingMap);
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
