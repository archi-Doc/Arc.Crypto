// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Arc.Crypto;

public static unsafe class Base64b
{
    private const int StackallocThreshold = 4096;

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool InternalFromByteArrayToUtf8(ReadOnlySpan<byte> bytes, Span<byte> utf8, out int bytesWritten)
    {
        fixed (byte* input = &MemoryMarshal.GetReference(bytes))
        fixed (byte* output = &MemoryMarshal.GetReference(utf8))
        {
            bytesWritten = EncodeBase64Core(input, output, bytes.Length);
            return true;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool InternalFromByteArrayToUtf16(ReadOnlySpan<byte> bytes, Span<char> chars, out int charsWritten)
    {
        fixed (byte* inData = &MemoryMarshal.GetReference(bytes))
        fixed (char* outChars = &MemoryMarshal.GetReference(chars))
        {
            charsWritten = EncodeBase64Core(inData, outChars, bytes.Length);
            return true;
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

    private static int EncodeBase64Core(byte* input, char* outChar, int length)
    {
        // SSE2
        var output = (byte*)outChar;
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

            Sse2.Store(output, Sse2.UnpackLow(result, Vector128<byte>.Zero));
            output += 16;
            Sse2.Store(output, Sse2.UnpackHigh(result, Vector128<byte>.Zero));
            output += 16;
        }

        return 32;
    }
}
