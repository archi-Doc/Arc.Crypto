// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Linq;
using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

/// <summary>
/// Tests <see cref="XxHash32"/> and <see cref="XxHash64"/> against System.IO.Hashing.
/// </summary>
public class XxHashTest
{
    private static readonly byte[] Data = CreateData();

    [Fact]
    public void OneShotMatchesSystemIOHashing()
    {
        // XxHash32 consumes 16-byte stripes, XxHash64 32-byte stripes; lengths up to 2000 run the main loops many times.
        for (var offset = 0; offset < 4; offset++)
        {// Offsets 1..3 read unaligned words.
            for (var length = 0; length <= 2000; length++)
            {
                var span = Data.AsSpan(offset, length);
                XxHash64.Hash64(span).Is(System.IO.Hashing.XxHash64.HashToUInt64(span));
                XxHash32.Hash32(span).Is(System.IO.Hashing.XxHash32.HashToUInt32(span));
            }
        }
    }

    [Fact]
    public void IncrementalMatchesSystemIOHashing()
    {
        var x64 = new XxHash64();
        var x32 = new XxHash32();
        foreach (var length in new[] { 0, 1, 3, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 1000, 4097, })
        {
            var span = Data.AsSpan(0, length);
            var expected64 = System.IO.Hashing.XxHash64.HashToUInt64(span);
            var expected32 = System.IO.Hashing.XxHash32.HashToUInt32(span);
            foreach (var chunk in new[] { 1, 3, 13, 16, 31, 32, 33, 100, 5000, })
            {
                x64.HashInitialize();
                x32.HashInitialize();
                for (var i = 0; i < length; i += chunk)
                {
                    var c = span.Slice(i, Math.Min(chunk, length - i));
                    x64.HashUpdate(c);
                    x32.HashUpdate(c);
                }

                // HashFinal writes the value in machine byte order (BitConverter).
                BitConverter.ToUInt64(x64.HashFinal()).Is(expected64);
                BitConverter.ToUInt32(x32.HashFinal()).Is(expected32);
            }

            // Array overloads.
            var array = Data.AsSpan(0, length + 5).ToArray();
            x64.HashInitialize();
            x64.HashUpdate(array, 5, length);
            BitConverter.ToUInt64(x64.HashFinal()).Is(System.IO.Hashing.XxHash64.HashToUInt64(array.AsSpan(5)));
            BitConverter.ToUInt64(x64.GetHash(array, 5, length)).Is(System.IO.Hashing.XxHash64.HashToUInt64(array.AsSpan(5)));
            x32.HashInitialize();
            x32.HashUpdate(array, 5, length);
            BitConverter.ToUInt32(x32.HashFinal()).Is(System.IO.Hashing.XxHash32.HashToUInt32(array.AsSpan(5)));
            BitConverter.ToUInt32(x32.GetHash(array, 5, length)).Is(System.IO.Hashing.XxHash32.HashToUInt32(array.AsSpan(5)));
        }
    }

    [Fact]
    public void ByteOutputIsMachineByteOrder()
    {
        var span = Data.AsSpan(0, 100);
        var x64 = new XxHash64();
        var x32 = new XxHash32();
        Assert.Equal(BitConverter.GetBytes(System.IO.Hashing.XxHash64.HashToUInt64(span)), x64.GetHash(span));
        Assert.Equal(BitConverter.GetBytes(System.IO.Hashing.XxHash32.HashToUInt32(span)), x32.GetHash(span));
        if (BitConverter.IsLittleEndian)
        {// System.IO.Hashing writes big-endian bytes, so the byte arrays are reversed on little-endian machines.
            Assert.Equal(Enumerable.Reverse(System.IO.Hashing.XxHash64.Hash(span)), x64.GetHash(span));
            Assert.Equal(Enumerable.Reverse(System.IO.Hashing.XxHash32.Hash(span)), x32.GetHash(span));
        }
    }

    [Fact]
    public void Properties()
    {
        var x64 = new XxHash64();
        x64.HashName.Is("xxHash64");
        x64.HashBits.Is(64u);
        x64.IsCryptographic.IsFalse();
        XxHash64.HashLength.Is(8);

        var x32 = new XxHash32();
        x32.HashName.Is("xxHash32");
        x32.HashBits.Is(32u);
        x32.IsCryptographic.IsFalse();
    }

    [Fact]
    public void HashFinalDoesNotReset()
    {
        var x64 = new XxHash64();
        var x32 = new XxHash32();
        x64.HashUpdate(Data.AsSpan(0, 40));
        x32.HashUpdate(Data.AsSpan(0, 40));
        Assert.Equal(x64.HashFinal(), x64.HashFinal());
        Assert.Equal(x32.HashFinal(), x32.HashFinal());

        // Further updates continue the same input.
        x64.HashUpdate(Data.AsSpan(40, 60));
        x32.HashUpdate(Data.AsSpan(40, 60));
        BitConverter.ToUInt64(x64.HashFinal()).Is(System.IO.Hashing.XxHash64.HashToUInt64(Data.AsSpan(0, 100)));
        BitConverter.ToUInt32(x32.HashFinal()).Is(System.IO.Hashing.XxHash32.HashToUInt32(Data.AsSpan(0, 100)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("abc")]
    [InlineData("日本語のテスト🌸🍣🚀 and a longer tail that exceeds thirty-two bytes")]
    public void StringOverloadsHashRawUtf16Bytes(string text)
    {
        var bytes = MemoryMarshal.AsBytes(text.AsSpan());
        XxHash64.Hash64(text).Is(System.IO.Hashing.XxHash64.HashToUInt64(bytes));
        XxHash32.Hash32(text).Is(System.IO.Hashing.XxHash32.HashToUInt32(bytes));
    }

    [Fact]
    public void NullStringIsEmpty()
    {
        XxHash64.Hash64((string)null!).Is(System.IO.Hashing.XxHash64.HashToUInt64(ReadOnlySpan<byte>.Empty));
        XxHash32.Hash32((string)null!).Is(System.IO.Hashing.XxHash32.HashToUInt32(ReadOnlySpan<byte>.Empty));
    }

    private static byte[] CreateData()
    {
        var data = new byte[5000];
        new Random(3).NextBytes(data);
        return data;
    }
}
