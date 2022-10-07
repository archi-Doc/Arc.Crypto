// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Xml.Linq;

namespace Arc.Crypto.Obsolete;

public static unsafe class Base64b
{
    private const int StackallocThreshold = 4096;

    private static readonly char[] Base64EncodeTable =
    {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    };

    private static readonly sbyte[] Base64DecodeTable;

    private static readonly byte[] Base64Utf8EncodeTable =
    {
            (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G', (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N', (byte)'O', (byte)'P',
            (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U', (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f',
            (byte)'g', (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n', (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u', (byte)'v',
            (byte)'w', (byte)'x', (byte)'y', (byte)'z', (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'+', (byte)'/',
    };

    static Base64b()
    {
        Base64DecodeTable = BuildDecodeTable(Base64EncodeTable);
    }

    /// <summary>
    /// Gets a length of the Base64-encoded string.
    /// </summary>
    /// <param name="length">A length of the byte array.</param>
    /// <returns>A length of the Base64-encoded string.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetBase64EncodeLength(int length)
    {
        if (length == 0)
        {
            return 0;
        }

        var v = ((length + 2) / 3) * 4;
        return v == 0 ? 4 : v;
    }

    /// <summary>
    /// Gets a maximum length of the output byte array.
    /// </summary>
    /// <param name="length">A length of the Base64-encoded string.</param>
    /// <returns>A maximum length of the output byte array.</returns>
    public static int GetMaxBase64DecodeLength(int length)
    {
        return (length / 4) * 3;
    }

    /// <summary>
    /// Decode from a Base64 (UTF-8) string to a byte array.
    /// </summary>
    /// <param name="utf8">The source Base64 (UTF-8) string.</param>
    /// <returns>A byte array. Returns null if the Base64 string is invalid.</returns>
    public static byte[]? FromUtf8ToByteArray(ReadOnlySpan<byte> utf8)
    {
        byte[]? pooledName = null;
        byte[]? result = null;
        var length = GetMaxBase64DecodeLength(utf8.Length);

        Span<byte> span = length <= StackallocThreshold ?
            stackalloc byte[length] :
            (pooledName = ArrayPool<byte>.Shared.Rent(length));

        if (InternalFromToUtf8ToByteArray(utf8, span, out var written))
        { // Success.
            result = span.Slice(0, written).ToArray();
        }

        if (pooledName != null)
        {
            ArrayPool<byte>.Shared.Return(pooledName);
        }

        return result;
    }

    /// <summary>
    /// Decode from a Base64 (UTF-16) string to a byte array.
    /// </summary>
    /// <param name="utf16">The source Base64 (UTF-16).</param>
    /// <returns>A Byte array. Returns null if the base64 string is invalid.</returns>
    public static byte[]? FromStringToByteArray(ReadOnlySpan<char> utf16)
    {
        byte[]? pooledName = null;
        byte[]? result = null;
        var length = GetMaxBase64DecodeLength(utf16.Length);

        Span<byte> span = length <= StackallocThreshold ?
            stackalloc byte[length] :
            (pooledName = ArrayPool<byte>.Shared.Rent(length));

        if (InternalFromToCharsToByteArray(utf16, span, out var written))
        { // Success.
            result = span.Slice(0, written).ToArray();
        }

        if (pooledName != null)
        {
            ArrayPool<byte>.Shared.Return(pooledName);
        }

        return result;
    }

    public static byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> bytes)
    {
        byte[]? pooledName = null;
        var length = GetBase64EncodeLength(bytes.Length);

        Span<byte> span = length <= StackallocThreshold ?
            stackalloc byte[length] :
            (pooledName = ArrayPool<byte>.Shared.Rent(length));

        InternalFromByteArrayToUtf8(bytes, span, out var written);
        var result = span.Slice(0, written).ToArray();

        if (pooledName != null)
        {
            ArrayPool<byte>.Shared.Return(pooledName);
        }

        return result;
    }

    /// <summary>
    /// Encode from a byte array to a Base64 (UTF-16) string.
    /// </summary>
    /// <param name="bytes">The source byte array.</param>
    /// <returns>A Base64 (UTF-16) string.</returns>
    public static string FromByteArrayToString(ReadOnlySpan<byte> bytes)
    {
        char[]? pooledName = null;
        var length = GetBase64EncodeLength(bytes.Length);

        Span<char> span = length <= (StackallocThreshold / 2) ?
            stackalloc char[length] :
            (pooledName = ArrayPool<char>.Shared.Rent(length));

        InternalFromByteArrayToUtf16(bytes, span, out var written);
        var result = new string(span.Slice(0, written));

        if (pooledName != null)
        {
            ArrayPool<char>.Shared.Return(pooledName);
        }

        return result;
    }

    /// <summary>
    /// Try decode from a Base64 (UTF-8) string to a byte array.
    /// </summary>
    /// <param name="utf8">The source UTF-8 string.</param>
    /// <param name="bytes">The destination buffer (minimum size GetMaxBase64DecodeLength()).</param>
    /// <param name="bytesWritten">The number of bytes consumed.</param>
    /// <returns>Returns true on success.</returns>
    public static bool InternalFromToUtf8ToByteArray(ReadOnlySpan<byte> utf8, Span<byte> bytes, out int bytesWritten)
    {
        fixed (byte* input = &MemoryMarshal.GetReference(utf8))
        fixed (byte* output = &MemoryMarshal.GetReference(bytes))
        {
            var inputRemaining = utf8.Length;
            var inputPosition = 0;
            var outputPosition = 0;

            if (Sse41.IsSupported)
            {
                if (!DecodeBase64ByteSse(input, ref inputPosition, ref inputRemaining, output, ref outputPosition))
                {
                    bytesWritten = 0;
                    return false;
                }
            }

            if (inputRemaining > 0)
            {
                if (!DecodeBase64ByteTable(input, ref inputPosition, ref inputRemaining, output, ref outputPosition, Base64DecodeTable))
                {
                    bytesWritten = 0;
                    return false;
                }
            }

            bytesWritten = outputPosition;
            return true;
        }
    }

    /// <summary>
    /// Try decode from a Base64 (UTF-16) string to a byte array.
    /// </summary>
    /// <param name="chars">The source string.</param>
    /// <param name="bytes">The destination buffer (minimum size GetMaxBase64DecodeLength()).</param>
    /// <param name="bytesWritten">The number of bytes consumed.</param>
    /// <returns>Returns true on success.</returns>
    public static bool InternalFromToCharsToByteArray(ReadOnlySpan<char> chars, Span<byte> bytes, out int bytesWritten)
    {
        fixed (char* input = &MemoryMarshal.GetReference(chars))
        fixed (byte* output = &MemoryMarshal.GetReference(bytes))
        {
            return DecodeBase64Core(input, output, 0, chars.Length, Base64DecodeTable, out bytesWritten);
        }
    }

    private static bool InternalFromByteArrayToUtf8(ReadOnlySpan<byte> bytes, Span<byte> utf8, out int bytesWritten)
    {
        fixed (byte* input = &MemoryMarshal.GetReference(bytes))
        fixed (byte* output = &MemoryMarshal.GetReference(utf8))
        {
            var inputRemaining = bytes.Length;
            var inputPosition = 0;
            var outputPosition = 0;

            if (Ssse3.IsSupported)
            {
                EncodeBase64ByteSse(input, ref inputPosition, ref inputRemaining, output, ref outputPosition);
            }

            if (inputRemaining > 0)
            {
                EncodeBase64ByteTable(input, ref inputPosition, ref inputRemaining, output, ref outputPosition, Base64Utf8EncodeTable);
            }

            bytesWritten = outputPosition;
            return true;
        }
    }

    private static bool InternalFromByteArrayToUtf16(ReadOnlySpan<byte> bytes, Span<char> chars, out int charsWritten)
    {
        fixed (byte* input = &MemoryMarshal.GetReference(bytes))
        fixed (char* output = &MemoryMarshal.GetReference(chars))
        {
            var inputRemaining = bytes.Length;
            var inputPosition = 0;
            var outputPosition = 0;

            if (Ssse3.IsSupported)
            {
                EncodeBase64CharSse(input, ref inputPosition, ref inputRemaining, output, ref outputPosition);
            }

            if (inputRemaining > 0)
            {
                EncodeBase64CharTable(input, ref inputPosition, ref inputRemaining, output, ref outputPosition, Base64EncodeTable);
            }

            charsWritten = outputPosition;
            return true;
        }
    }

    private static bool DecodeBase64Core(char* inChars, byte* outData, int offset, int length, sbyte[] decodeTable, out int written)
    {
        if (length == 0)
        {
            written = 0;
            return true;
        }

        var loopLength = offset + length - 4; // skip last-chunk

        var i = 0;
        var j = 0;
        fixed (sbyte* table = &decodeTable[0])
        {
            for (i = offset; i < loopLength;)
            {
                ref var i0 = ref table[inChars[i]];
                ref var i1 = ref table[inChars[i + 1]];
                ref var i2 = ref table[inChars[i + 2]];
                ref var i3 = ref table[inChars[i + 3]];

#pragma warning disable CS0675
                if (((i0 | i1 | i2 | i3) & 0b10000000) == 0b10000000)
                {
                    written = 0;
                    return false;
                }
#pragma warning restore CS0675

                // 6 + 2(4)
                // 4 + 4(2)
                // 2 + 6
                var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                var r2 = (byte)(((i2 & 0b00000011) << 6) | (i3 & 0b00111111));

                outData[j] = r0;
                outData[j + 1] = r1;
                outData[j + 2] = r2;

                i += 4;
                j += 3;
            }

            var rest = length - i;

            // Base64
            if (rest != 4)
            {
                written = 0;
                return false;
            }

            {
                ref var i0 = ref table[inChars[i]];
                ref var i1 = ref table[inChars[i + 1]];
                ref var i2 = ref table[inChars[i + 2]];
                ref var i3 = ref table[inChars[i + 3]];

                if (i3 == -2)
                {
                    if (i2 == -2)
                    {
                        if (i1 == -2)
                        {
                            if (i0 == -2)
                            {
                                // ====
                            }

                            // *===
                            written = 0;
                            return false;
                        }

                        {
                            // **==
                            if (IsInvalid(ref i0, ref i1))
                            {
                                written = 0;
                                return false;
                            }

                            var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                            outData[j] = r0;
                            j += 1;
                            written = j;
                            return true;
                        }
                    }

                    {
                        // ***=
                        if (IsInvalid(ref i0, ref i1, ref i2))
                        {
                            written = 0;
                            return false;
                        }

                        var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                        var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                        outData[j] = r0;
                        outData[j + 1] = r1;
                        j += 2;
                        written = j;
                        return true;
                    }
                }
                else
                {
                    // ****
                    if (IsInvalid(ref i0, ref i1, ref i2, ref i3))
                    {
                        written = 0;
                        return false;
                    }

                    var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                    var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                    var r2 = (byte)(((i2 & 0b00000011) << 6) | (i3 & 0b00111111));
                    outData[j] = r0;
                    outData[j + 1] = r1;
                    outData[j + 2] = r2;
                    j += 3;
                    written = j;
                    return true;
                }
            }
        }
    }

    private static int EncodeBase64Core(byte* input, byte* output, int length)
    {
        // SSE2
        var shuf = Vector128.Create((byte)1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);

        for (var i = 0; i < length; i += 4 * 3)
        {
            var in0 = Sse2.LoadVector128(input + i);
            in0 = Ssse3.Shuffle(in0, shuf);

            var t0 = Sse2.And(in0, Vector128.Create(0x0fc0fc00).AsByte());
            var t1 = Sse2.MultiplyHigh(t0.AsUInt16(), Vector128.Create(0x04000040).AsUInt16());
            var t2 = Sse2.And(in0, Vector128.Create(0x003f03f0).AsByte());
            var t3 = Sse2.MultiplyLow(t2.AsUInt16(), Vector128.Create(0x01000010).AsUInt16());
            var indices = Sse2.Or(t1, t3).AsByte();

            var result = Sse2.SubtractSaturate(indices, Vector128.Create((byte)51));
            var less = Sse2.CompareGreaterThan(Vector128.Create((sbyte)26), indices.AsSByte());
            result = Sse2.Or(result, Sse2.And(less, Vector128.Create((sbyte)13)).AsByte());

            var shift = Vector128.Create(71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 237, 240, 65, 0, 0);
            result = Ssse3.Shuffle(shift, result);
            result = Sse2.Add(result, indices);

            Sse2.Store(output, result);
            output += 16;
        }

        // AVX2
        /*for (var i = 0; i < length; i += 2 * 4 * 3)
        {
            var lo = Sse2.LoadVector128(input + i);
            var hi = Sse2.LoadVector128(input + i + (4 * 3));
            // var shuf = Vector256.Create((byte)10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1, 10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1);
            var shuf = Vector256.Create((byte)1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10, 1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);

            var in0 = Avx2.Shuffle(Vector256.Create(hi, lo), shuf);

            var t0 = Avx2.And(in0, Vector256.Create(0x0fc0fc00).AsByte());
            var t1 = Avx2.MultiplyHigh(t0.AsUInt16(), Vector256.Create(0x04000040).AsUInt16());
            var t2 = Avx2.And(in0, Vector256.Create(0x003f03f0).AsByte());
            var t3 = Avx2.MultiplyLow(t2.AsUInt16(), Vector256.Create(0x01000010).AsUInt16());

            // var indices = Avx2.Or(t1, t3).AsSByte();
            // var result = Vector256.Create((sbyte)65);
            // var ge26 = Avx2.CompareGreaterThan(indices, Vector256.Create((sbyte)25));
            // var ge52 = Avx2.CompareGreaterThan(indices, Vector256.Create((sbyte)51));
            // var eq62 = Avx2.CompareEqual(indices, Vector256.Create((sbyte)62));
            // var eq63 = Avx2.CompareEqual(indices, Vector256.Create((sbyte)63));

            // result = Avx2.Add(result, Avx2.And(ge26, Vector256.Create((sbyte)6)));
            // result = Avx2.Subtract(result, Avx2.And(ge52, Vector256.Create((sbyte)75)));
            // result = Avx2.Add(result, Avx2.And(eq62, Vector256.Create(unchecked((sbyte)241))));
            // result = Avx2.Subtract(result, Avx2.And(eq63, Vector256.Create((sbyte)12)));

            // result = Avx2.Add(result, indices);

            var indices = Avx2.Or(t1, t3).AsSByte();
            var result = Avx2.SubtractSaturate(indices.AsByte(), Vector256.Create((byte)51));
            var less = Avx2.CompareGreaterThan(Vector256.Create((sbyte)26), indices);
            result = Avx2.Or(result, Avx2.And(less, Vector256.Create((sbyte)13)).AsByte());

            var shift = Vector256.Create(71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 237, 240, 65, 0, 0, 71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 237, 240, 65, 0, 0);
            result = Avx2.Shuffle(shift, result);
            result = Avx2.Add(result, indices.AsByte());

            Avx2.Store(output, result.AsByte());
            output += 32;
        }*/

        return 32;
    }

    private static void EncodeBase64ByteSse(byte* input, ref int inputPosition, ref int inputRemaining, byte* outBytes, ref int outputPosition)
    {
        input += inputPosition;
        outBytes += outputPosition;

        // SSE2
        var output = (byte*)outBytes;
        var shuf = Vector128.Create((byte)1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);
        while (inputRemaining >= 16)
        {
            var in0 = Sse2.LoadVector128(input); // 16 bytes
            in0 = Ssse3.Shuffle(in0, shuf);

            var t0 = Sse2.And(in0, Vector128.Create(0x0fc0fc00).AsByte());
            var t1 = Sse2.MultiplyHigh(t0.AsUInt16(), Vector128.Create(0x04000040).AsUInt16());
            var t2 = Sse2.And(in0, Vector128.Create(0x003f03f0).AsByte());
            var t3 = Sse2.MultiplyLow(t2.AsUInt16(), Vector128.Create(0x01000010).AsUInt16());
            var indices = Sse2.Or(t1, t3).AsByte();

            var result = Sse2.SubtractSaturate(indices, Vector128.Create((byte)51));
            var less = Sse2.CompareGreaterThan(Vector128.Create((sbyte)26), indices.AsSByte());
            result = Sse2.Or(result, Sse2.And(less, Vector128.Create((sbyte)13)).AsByte());

            var shift = Vector128.Create(71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 237, 240, 65, 0, 0);
            result = Ssse3.Shuffle(shift, result);
            result = Sse2.Add(result, indices);

            Sse2.Store(output, result);
            output += 16;

            input += 12;
            inputPosition += 12;
            inputRemaining -= 12;
            outputPosition += 16;
        }
    }

    private static void EncodeBase64CharSse(byte* input, ref int inputPosition, ref int inputRemaining, char* outChars, ref int outputPosition)
    {
        input += inputPosition;
        outChars += outputPosition;

        // SSE2
        var output = (byte*)outChars;
        var shuf = Vector128.Create((byte)1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);
        while (inputRemaining >= 16)
        {
            var in0 = Sse2.LoadVector128(input); // 16 bytes
            in0 = Ssse3.Shuffle(in0, shuf);

            var t0 = Sse2.And(in0, Vector128.Create(0x0fc0fc00).AsByte());
            var t1 = Sse2.MultiplyHigh(t0.AsUInt16(), Vector128.Create(0x04000040).AsUInt16());
            var t2 = Sse2.And(in0, Vector128.Create(0x003f03f0).AsByte());
            var t3 = Sse2.MultiplyLow(t2.AsUInt16(), Vector128.Create(0x01000010).AsUInt16());
            var indices = Sse2.Or(t1, t3).AsByte();

            var result = Sse2.SubtractSaturate(indices, Vector128.Create((byte)51));
            var less = Sse2.CompareGreaterThan(Vector128.Create((sbyte)26), indices.AsSByte());
            result = Sse2.Or(result, Sse2.And(less, Vector128.Create((sbyte)13)).AsByte());

            var shift = Vector128.Create(71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 237, 240, 65, 0, 0);
            result = Ssse3.Shuffle(shift, result);
            result = Sse2.Add(result, indices);

            Sse2.Store(output, Sse2.UnpackLow(result, Vector128<byte>.Zero));
            output += 16;
            Sse2.Store(output, Sse2.UnpackHigh(result, Vector128<byte>.Zero));
            output += 16;

            input += 12;
            inputPosition += 12;
            inputRemaining -= 12;
            outputPosition += 16;
        }
    }

    private static void EncodeBase64ByteTable(byte* input, ref int inputPosition, ref int inputRemaining, byte* outBytes, ref int outputPosition, byte[] encodeTable)
    {
        input += inputPosition;
        outBytes += outputPosition;

        var mod3 = inputRemaining % 3;
        var loopLength = inputRemaining - mod3;
        var i = 0;
        var j = 0;
        fixed (byte* table = &encodeTable[0])
        {
            for (i = 0; i < loopLength; i += 3)
            {
                outBytes[j] = table[(input[i] & 0b11111100) >> 2];
                outBytes[j + 1] = table[((input[i] & 0b00000011) << 4) | ((input[i + 1] & 0b11110000) >> 4)];
                outBytes[j + 2] = table[((input[i + 1] & 0b00001111) << 2) | ((input[i + 2] & 0b11000000) >> 6)];
                outBytes[j + 3] = table[input[i + 2] & 0b00111111];
                j += 4;
            }

            i = loopLength;

            if (mod3 == 2)
            {
                outBytes[j] = table[(input[i] & 0b11111100) >> 2];
                outBytes[j + 1] = table[((input[i] & 0b00000011) << 4) | ((input[i + 1] & 0b11110000) >> 4)];
                outBytes[j + 2] = table[(input[i + 1] & 0b00001111) << 2];
                outBytes[j + 3] = (byte)'='; // padding
                j += 4;
            }
            else if (mod3 == 1)
            {
                outBytes[j] = table[(input[i] & 0b11111100) >> 2];
                outBytes[j + 1] = table[(input[i] & 0b00000011) << 4];
                outBytes[j + 2] = (byte)'=';
                outBytes[j + 3] = (byte)'=';
                j += 4;
            }
        }

        inputPosition += inputRemaining;
        inputRemaining = 0;
        outputPosition += j;
    }

    private static void EncodeBase64CharTable(byte* input, ref int inputPosition, ref int inputRemaining, char* outChars, ref int outputPosition, char[] encodeTable)
    {
        input += inputPosition;
        outChars += outputPosition;

        var mod3 = inputRemaining % 3;
        var loopLength = inputRemaining - mod3;
        var i = 0;
        var j = 0;
        fixed (char* table = &encodeTable[0])
        {
            for (i = 0; i < loopLength; i += 3)
            {
                outChars[j] = table[(input[i] & 0b11111100) >> 2];
                outChars[j + 1] = table[((input[i] & 0b00000011) << 4) | ((input[i + 1] & 0b11110000) >> 4)];
                outChars[j + 2] = table[((input[i + 1] & 0b00001111) << 2) | ((input[i + 2] & 0b11000000) >> 6)];
                outChars[j + 3] = table[input[i + 2] & 0b00111111];
                j += 4;
            }

            i = loopLength;

            if (mod3 == 2)
            {
                outChars[j] = table[(input[i] & 0b11111100) >> 2];
                outChars[j + 1] = table[((input[i] & 0b00000011) << 4) | ((input[i + 1] & 0b11110000) >> 4)];
                outChars[j + 2] = table[(input[i + 1] & 0b00001111) << 2];
                outChars[j + 3] = '='; // padding
                j += 4;
            }
            else if (mod3 == 1)
            {
                outChars[j] = table[(input[i] & 0b11111100) >> 2];
                outChars[j + 1] = table[(input[i] & 0b00000011) << 4];
                outChars[j + 2] = '=';
                outChars[j + 3] = '=';
                j += 4;
            }
        }

        inputPosition += inputRemaining;
        inputRemaining = 0;
        outputPosition += j;
    }

    private static bool DecodeBase64ByteSse(byte* input, ref int inputPosition, ref int inputRemaining, byte* outBytes, ref int outputPosition)
    {
        input += inputPosition;
        outBytes += outputPosition;

        // SSE2
        var output = (byte*)outBytes;
        var shuf = Vector128.Create((byte)2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 0xff, 0xff, 0xff, 0xff);
        while (inputRemaining >= 20)
        {// 16 = 15 + '#'
            var values = Sse2.LoadVector128(input);

            // lookup
            if (!DecodeLookup(ref values))
            {
                return false;
            }

            // pack
            var m0 = Ssse3.MultiplyAddAdjacent(values, Vector128.Create(0x01400140).AsSByte());
            var merged = Sse2.MultiplyAddAdjacent(m0, Vector128.Create(0x00011000).AsInt16());

            var shuffled = Ssse3.Shuffle(merged.AsByte(), shuf);

            Sse2.Store(output, shuffled);
            output += 12;

            input += 16;
            inputPosition += 16;
            inputRemaining -= 16;
            outputPosition += 12;
        }

        return true;
    }

    private static bool DecodeLookup(ref Vector128<byte> input)
    {
        var higher_nibble = Sse2.And(Sse2.ShiftRightLogical(input.AsUInt32(), 4).AsByte(), Vector128.Create((byte)0x0f));
        var lower_nibble = Sse2.And(input, Vector128.Create((byte)0x0f));

        var shiftLUT = Vector128.Create(0, 0, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0).AsByte();
        var maskLUT = Vector128.Create(0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf0, 0x54, 0x50, 0x50, 0x50, 0x54);
        var bitposLUT = Vector128.Create(0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

        var sh = Ssse3.Shuffle(shiftLUT, higher_nibble);
        var eq_2f = Sse2.CompareEqual(input, Vector128.Create((byte)0x2f));
        var shift = Sse41.BlendVariable(sh, Vector128.Create((byte)16), eq_2f);

        var m = Ssse3.Shuffle(maskLUT, lower_nibble);
        var bit = Ssse3.Shuffle(bitposLUT, higher_nibble);

        var nonMatch = Sse2.CompareEqual(Sse2.And(m, bit), Vector128<byte>.Zero);
        var mask = Sse2.MoveMask(nonMatch);
        if (mask != 0)
        {
            return false;
        }

        input = Sse2.Add(input, shift);
        return true;
    }

    private static bool DecodeBase64ByteTable(byte* input, ref int inputPosition, ref int inputRemaining, byte* outBytes, ref int outputPosition, sbyte[] decodeTable)
    {
        if (inputRemaining == 0)
        {
            return true;
        }

        input += inputPosition;
        outBytes += outputPosition;
        var loopLength = inputRemaining - 4; // skip last-chunk

        var i = 0;
        var j = 0;
        fixed (sbyte* table = &decodeTable[0])
        {
            for (i = 0; i < loopLength;)
            {
                ref var i0 = ref table[input[i]];
                ref var i1 = ref table[input[i + 1]];
                ref var i2 = ref table[input[i + 2]];
                ref var i3 = ref table[input[i + 3]];

#pragma warning disable CS0675
                if (((i0 | i1 | i2 | i3) & 0b10000000) == 0b10000000)
                {
                    return false;
                }
#pragma warning restore CS0675

                var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                var r2 = (byte)(((i2 & 0b00000011) << 6) | (i3 & 0b00111111));

                outBytes[j] = r0;
                outBytes[j + 1] = r1;
                outBytes[j + 2] = r2;

                i += 4;
                j += 3;
            }

            var rest = inputRemaining - i;

            // Base64
            if (rest != 4)
            {
                return false;
            }

            {
                ref var i0 = ref table[input[i]];
                ref var i1 = ref table[input[i + 1]];
                ref var i2 = ref table[input[i + 2]];
                ref var i3 = ref table[input[i + 3]];

                if (i3 == -2)
                {
                    if (i2 == -2)
                    {
                        if (i1 == -2)
                        {
                            return false;
                        }

                        if (IsInvalid(ref i0, ref i1))
                        {
                            return false;
                        }

                        outBytes[j] = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                        j += 1;
                        goto Success;
                    }

                    if (IsInvalid(ref i0, ref i1, ref i2))
                    {
                        return false;
                    }

                    outBytes[j] = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                    outBytes[j + 1] = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                    j += 2;
                    goto Success;
                }
                else
                {
                    if (IsInvalid(ref i0, ref i1, ref i2, ref i3))
                    {
                        return false;
                    }

                    outBytes[j] = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                    outBytes[j + 1] = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                    outBytes[j + 2] = (byte)(((i2 & 0b00000011) << 6) | (i3 & 0b00111111));
                    j += 3;
                    goto Success;
                }
            }
        }

Success:
        inputPosition += inputRemaining;
        inputRemaining = 0;
        outputPosition += j;
        return true;
    }

    private static sbyte[] BuildDecodeTable(char[] encodeTable)
    {
        var table = encodeTable.Select((x, i) => (x, i)).ToDictionary(x => x.x, x => x.i);
        var array = new sbyte[char.MaxValue];
        for (int i = 0; i < char.MaxValue; i++)
        {
            if (table.TryGetValue((char)i, out var v))
            {
                array[i] = (sbyte)v;
            }
            else
            {
                if ((char)i == '=')
                {
                    array[i] = -2;
                }
                else
                {
                    array[i] = -1;
                }
            }
        }

        return array;
    }

#pragma warning disable CS0675
    private static bool IsInvalid(ref sbyte i0)
        => (i0 & 0b10000000) == 0b10000000;

    private static bool IsInvalid(ref sbyte i0, ref sbyte i1)
        => ((i0 | i1) & 0b10000000) == 0b10000000;

    private static bool IsInvalid(ref sbyte i0, ref sbyte i1, ref sbyte i2)
        => ((i0 | i1 | i2) & 0b10000000) == 0b10000000;

    private static bool IsInvalid(ref sbyte i0, ref sbyte i1, ref sbyte i2, ref sbyte i3)
        => ((i0 | i1 | i2 | i3) & 0b10000000) == 0b10000000;
}
