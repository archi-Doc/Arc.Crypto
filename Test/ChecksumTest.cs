// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using Arc.Crypto;
using Xunit;
using ArmCrc32 = System.Runtime.Intrinsics.Arm.Crc32;

namespace Test;

/// <summary>
/// Checks <see cref="Crc32"/> and <see cref="Adler32"/> against independent oracles on every implementation path available on the machine.
/// </summary>
public class ChecksumTest
{
    private const uint Crc32Mask = 0xFFFFFFFF;
    private const uint AdlerModulus = 65521;
    private const int AdlerMaxLength = (4 * 5552) + 64;

    /// <summary>
    /// Lengths 0..10000 plus lengths around multiples of 3800 (former chunk size), 5536 (AVX2 chunk) and 5552 (NMAX; SSSE3 and scalar chunk).
    /// </summary>
    private static readonly int[] AdlerLengths = Enumerable.Range(0, 10001).Concat(AdlerBoundaryLengths()).Distinct().ToArray();

    [Fact]
    public void Crc32MatchesSystemIOHashingForAllLengths()
    {
        var data = CreateRandomData(2048 + 8, 1);
        foreach (var offset in new[] { 0, 1, 3, 8 })
        {
            for (var length = 0; length <= 2048; length++)
            {
                var span = data.AsSpan(offset, length);
                CheckCrc32Paths(System.IO.Hashing.Crc32.HashToUInt32(span), span, offset);
            }
        }
    }

    [Theory]
    [InlineData(65536)]
    [InlineData((1 << 20) + 13)]
    public void Crc32MatchesSystemIOHashingForLargeInputs(int length)
    {
        var data = CreateRandomData(length + 5, 2);
        var crc = new Crc32();
        foreach (var offset in new[] { 0, 5 })
        {
            var span = data.AsSpan(offset, length);
            var expected = System.IO.Hashing.Crc32.HashToUInt32(span);
            CheckCrc32Paths(expected, span, offset);

            foreach (var chunk in new[] { 15, 16, 17, 127, 128, 129, 4095, 65536 })
            {
                crc.HashInitialize();
                for (var i = 0; i < length; i += chunk)
                {
                    crc.HashUpdate(span.Slice(i, Math.Min(chunk, length - i)));
                }

                Check(expected, BitConverter.ToUInt32(crc.HashFinal()), $"HashUpdate chunk {chunk}", offset, length);
            }
        }
    }

    [Fact]
    public void Crc32IncrementalUpdateMatchesSystemIOHashing()
    {
        var data = CreateRandomData(20000, 3);
        var crc = new Crc32();
        foreach (var length in new[] { 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 1000, 3000 })
        {
            var span = data.AsSpan(0, length);
            var expected = System.IO.Hashing.Crc32.HashToUInt32(span);
            foreach (var chunk in new[] { 1, 3, 7, 8, 9, 15, 16, 17, 31, 63, 64, 65, 100, 127, 128, 129, 200 })
            {
                crc.HashInitialize();
                for (var i = 0; i < length; i += chunk)
                {
                    crc.HashUpdate(span.Slice(i, Math.Min(chunk, length - i)));
                }

                Check(expected, BitConverter.ToUInt32(crc.HashFinal()), $"HashUpdate chunk {chunk}", 0, length);
            }
        }

        // Random split points, including empty updates.
        var random = new Xoshiro256StarStar(4);
        for (var round = 0; round < 20; round++)
        {
            crc.HashInitialize();
            var position = 0;
            while (position < data.Length)
            {
                var size = Math.Min(random.NextInt32(300), data.Length - position);
                crc.HashUpdate(data, position, size);
                position += size;
            }

            Check(System.IO.Hashing.Crc32.HashToUInt32(data), BitConverter.ToUInt32(crc.HashFinal()), "random splits", 0, data.Length);
        }
    }

    [Fact]
    public void Adler32KnownAnswer()
    {
        // https://en.wikipedia.org/wiki/Adler-32 (example: "Wikipedia").
        Adler32.Hash32("Wikipedia"u8).Is(0x11E60398u);
    }

    [Fact]
    public void Adler32MatchesReferenceForAllLengths()
    {
        foreach (var allOnes in new[] { false, true })
        {
            var data = allOnes ? CreateFilledData(AdlerMaxLength + 3, 0xFF) : CreateRandomData(AdlerMaxLength + 3, 5);
            foreach (var offset in new[] { 0, 3 })
            {
                // 0xFFF0FFF0 (s1 = s2 = 65520) is the largest valid state, the worst case for overflow.
                foreach (var start in new uint[] { 1, 0xFFF0FFF0, (40000u << 16) | 12345u })
                {
                    var expected = ReferenceAdler32Prefixes(start, data.AsSpan(offset, AdlerMaxLength));
                    foreach (var length in AdlerLengths)
                    {
                        if (offset != 0 && length > 1100 && length <= 10000)
                        {// Unaligned starts: lengths up to 1100 and the boundary lengths above 10000 (the paths depend only on the length).
                            continue;
                        }

                        var span = data.AsSpan(offset, length);
                        if (start == 1)
                        {
                            Check(expected[length], Adler32.Hash32(span), "Hash32", offset, length);
                        }

                        CheckAdler32Paths(expected[length], start, span, offset);
                    }
                }
            }
        }
    }

    [Fact]
    public void Adler32MatchesReferenceForLargeAllOnesInput()
    {
        const int length = (3 << 20) + 7;
        var data = CreateFilledData(length, 0xFF);
        var expected = ReferenceAdler32(1, data);
        Check(expected, Adler32.Hash32(data), "Hash32", 0, length);
        CheckAdler32Paths(expected, 1, data, 0);

        var adler = new Adler32();
        foreach (var chunk in new[] { 5551, 5553, 65537, 1 << 20 })
        {
            adler.HashInitialize();
            for (var i = 0; i < length; i += chunk)
            {
                adler.HashUpdate(data.AsSpan(i, Math.Min(chunk, length - i)));
            }

            Check(expected, BitConverter.ToUInt32(adler.HashFinal()), $"HashUpdate chunk {chunk}", 0, length);
        }
    }

    [Fact]
    public void Adler32IncrementalUpdateMatchesReference()
    {
        var random = new Xoshiro256StarStar(6);
        foreach (var allOnes in new[] { false, true })
        {
            var data = allOnes ? CreateFilledData(40000, 0xFF) : CreateRandomData(40000, 7);
            var adler = new Adler32();
            for (var round = 0; round < 10; round++)
            {
                adler.HashInitialize();
                var expected = 1u;
                var position = 0;
                while (position < data.Length)
                {
                    var size = Math.Min(random.NextInt32(7000), data.Length - position);
                    var span = data.AsSpan(position, size);
                    adler.HashUpdate(span);
                    expected = ReferenceAdler32(expected, span);
                    position += size;
                }

                Check(expected, BitConverter.ToUInt32(adler.HashFinal()), "random splits", 0, data.Length);
            }
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3799)]
    [InlineData(3800)]
    [InlineData(3801)]
    [InlineData(5552)]
    [InlineData(5553)]
    [InlineData(7600)]
    [InlineData(100_000)]
    [InlineData(1_000_000)]
    public void Adler32MatchesZLibStreamTrailer(int length)
    {
        foreach (var allOnes in new[] { false, true })
        {
            var data = allOnes ? CreateFilledData(length, 0xFF) : CreateRandomData(length, (ulong)length);
            var expected = ZLibAdler32(data);
            Check(expected, Adler32.Hash32(data), "Hash32", 0, length);

            var adler = new Adler32();
            for (var i = 0; i < length; i += 777)
            {
                adler.HashUpdate(data, i, Math.Min(777, length - i));
            }

            Check(expected, BitConverter.ToUInt32(adler.HashFinal()), "HashUpdate chunk 777", 0, length);
        }
    }

    [Theory]
    [InlineData("Adler-32")]
    [InlineData("CRC-32")]
    public void ChecksumMetadataAndHashFinal(string name)
    {
        var isCrc = name == "CRC-32";
        IHash hash = isCrc ? new Crc32() : new Adler32();
        var data = CreateRandomData(300, 8);
        var expected = isCrc ? Crc32.Hash32(data) : Adler32.Hash32(data);

        hash.HashName.Is(name);
        hash.HashBits.Is(32u);
        hash.IsCryptographic.IsFalse();
        (isCrc ? Crc32.HashLength : Adler32.HashLength).Is(4);

        // The byte output is the numeric value in native byte order.
        hash.GetHash(data).Is(BitConverter.GetBytes(expected));
        hash.GetHash(data, 10, 100).Is(hash.GetHash(data.AsSpan(10, 100)));

        hash.HashInitialize();
        hash.HashUpdate(data, 0, 120);
        hash.HashUpdate(data.AsSpan(120));
        var first = hash.HashFinal();
        first.Is(BitConverter.GetBytes(expected));

        var second = hash.HashFinal();
        if (isCrc)
        {// Crc32.HashFinal resets the state.
            second.Is(hash.GetHash(ReadOnlySpan<byte>.Empty));
            hash.HashUpdate(data);
            hash.HashFinal().Is(first);
        }
        else
        {// Adler32.HashFinal does not reset the state: appending continues the same stream.
            second.Is(first);
            hash.HashUpdate(data);
            hash.HashFinal().Is(hash.GetHash(data.Concat(data).ToArray()));
        }
    }

    [Fact]
    public void StringOverloadsHashUtf16CodeUnits()
    {
        var text = "abc\u00e9\u3042";
        var codeUnits = MemoryMarshal.AsBytes(text.AsSpan());
        Crc32.Hash32(text).Is(Crc32.Hash32(codeUnits));
        Adler32.Hash32(text).Is(Adler32.Hash32(codeUnits));

        // Not the CRC-32 check value of the UTF-8 (ASCII) bytes, 0xCBF43926.
        Crc32.Hash32("123456789").IsNot(0xCBF43926u);

        if (BitConverter.IsLittleEndian)
        {
            var utf16 = Encoding.Unicode.GetBytes(text);
            Crc32.Hash32(text).Is(System.IO.Hashing.Crc32.HashToUInt32(utf16));
            Adler32.Hash32(text).Is(ReferenceAdler32(1, utf16));
        }
    }

    private static IEnumerable<int> AdlerBoundaryLengths()
    {
        foreach (var chunk in new[] { 3800, 5536, 5552 })
        {
            for (var k = 1; k <= 4; k++)
            {
                foreach (var delta in new[] { -33, -32, -17, -16, -1, 0, 1, 15, 16, 31, 32 })
                {
                    yield return (k * chunk) + delta;
                }
            }
        }

        yield return AdlerMaxLength;
    }

    private static void CheckCrc32Paths(uint expected, ReadOnlySpan<byte> span, int offset)
    {
        Check(expected, Crc32.Hash32(span), "Hash32", offset, span.Length);
        Check(expected, Crc32.UpdateTable(Crc32Mask, span) ^ Crc32Mask, "table", offset, span.Length);
        if (Crc32.IsVectorizedSupported && span.Length >= 16)
        {
            Check(expected, Crc32.UpdateVectorized(Crc32Mask, span) ^ Crc32Mask, "vectorized", offset, span.Length);
        }

        if (ArmCrc32.Arm64.IsSupported)
        {
            Check(expected, Crc32.UpdateArm64(Crc32Mask, span) ^ Crc32Mask, "Arm64", offset, span.Length);
        }
    }

    private static void CheckAdler32Paths(uint expected, uint start, ReadOnlySpan<byte> span, int offset)
    {
        Check(expected, Adler32.UpdateScalar(start, span), $"scalar from {start:X8}", offset, span.Length);
        if (Ssse3.IsSupported)
        {
            Check(expected, Adler32.UpdateVector128(start, span), $"Vector128 from {start:X8}", offset, span.Length);
        }

        if (Avx2.IsSupported)
        {
            Check(expected, Adler32.UpdateVector256(start, span), $"Vector256 from {start:X8}", offset, span.Length);
        }
    }

    private static void Check(uint expected, uint actual, string path, int offset, int length)
    {
        if (actual != expected)
        {
            Assert.Fail($"{path}, offset {offset}, length {length}: expected {expected:X8}, actual {actual:X8}.");
        }
    }

    /// <summary>
    /// Straightforward Adler-32 (RFC 1950) with a modulo after every byte.
    /// </summary>
    private static uint ReferenceAdler32(uint adler, ReadOnlySpan<byte> data)
    {
        var s1 = adler & 0xFFFF;
        var s2 = adler >> 16;
        foreach (var x in data)
        {
            s1 = (s1 + x) % AdlerModulus;
            s2 = (s2 + s1) % AdlerModulus;
        }

        return (s2 << 16) | s1;
    }

    /// <summary>
    /// Reference checksums of every prefix: element n is the checksum of the first n bytes.
    /// </summary>
    private static uint[] ReferenceAdler32Prefixes(uint adler, ReadOnlySpan<byte> data)
    {
        var result = new uint[data.Length + 1];
        var s1 = adler & 0xFFFF;
        var s2 = adler >> 16;
        result[0] = adler;
        for (var i = 0; i < data.Length; i++)
        {
            s1 = (s1 + data[i]) % AdlerModulus;
            s2 = (s2 + s1) % AdlerModulus;
            result[i + 1] = (s2 << 16) | s1;
        }

        return result;
    }

    /// <summary>
    /// Adler-32 computed by zlib: the last four bytes of a zlib stream (RFC 1950), big-endian.
    /// </summary>
    private static uint ZLibAdler32(byte[] data)
    {
        using var stream = new MemoryStream();
        using (var zlib = new ZLibStream(stream, CompressionLevel.NoCompression, true))
        {
            zlib.Write(data);
        }

        return BinaryPrimitives.ReadUInt32BigEndian(stream.ToArray().AsSpan(^4));
    }

    private static byte[] CreateRandomData(int length, ulong seed)
    {
        var data = new byte[length];
        new Xoshiro256StarStar(seed).NextBytes(data);
        return data;
    }

    private static byte[] CreateFilledData(int length, byte value)
    {
        var data = new byte[length];
        Array.Fill(data, value);
        return data;
    }
}
