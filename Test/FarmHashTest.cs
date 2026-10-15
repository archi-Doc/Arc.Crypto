// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using Xunit;

namespace XunitTest;

public class FarmHashTest
{
    private static readonly byte[] SelfTestData = CreateSelfTestData();

    /// <summary>
    /// Known answers from Google's FarmHash self-test: farmhash.cc (https://github.com/google/farmhash), namespace farmhashxoTest.
    /// Self-test case i hashes <c>data[offset..offset + length]</c> of the generated test data (offset = i * i and length = i for i &lt; 299, then offset 0 with growing lengths),
    /// and <c>expected[6i + 4]</c>, <c>expected[6i + 5]</c> are the high and low 32 bits of <c>farmhashxo::Hash64</c>.
    /// The cases cover every length class (0-16, 17-32, 33-64, 65-96, 97-256, over 256) and multi-block inputs up to 1 MiB.
    /// </summary>
    /// <param name="offset">The offset into the self-test data.</param>
    /// <param name="length">The input length.</param>
    /// <param name="expected">farmhashxo::Hash64 of the input.</param>
    [Theory]
    [InlineData(0, 0, 0x9AE16A3B2F90404FUL)] // case 0
    [InlineData(1, 1, 0x541150E87F415E96UL)] // case 1
    [InlineData(4, 2, 0x0F3786A4B25827C1UL)] // case 2
    [InlineData(9, 3, 0xEF923A7A1AF78EABUL)] // case 3
    [InlineData(16, 4, 0x11DF592596F41D88UL)] // case 4
    [InlineData(49, 7, 0x1B5A063FB4C7F9F1UL)] // case 7
    [InlineData(64, 8, 0xA0F10149A0E538D6UL)] // case 8
    [InlineData(81, 9, 0xFB8D9C70660B910BUL)] // case 9
    [InlineData(225, 15, 0x44473E03BE306C88UL)] // case 15
    [InlineData(256, 16, 0x03EAD5F21D344056UL)] // case 16
    [InlineData(289, 17, 0x6ABBFDE37EE03B5BUL)] // case 17
    [InlineData(576, 24, 0x36A097AA49519D97UL)] // case 24
    [InlineData(961, 31, 0x55BDB0E71E3EDEBDUL)] // case 31
    [InlineData(1024, 32, 0x0782FA1B08B475E7UL)] // case 32
    [InlineData(1089, 33, 0x3B09D6F3B6340467UL)] // case 33
    [InlineData(2304, 48, 0xF84C256AF9FEB14BUL)] // case 48
    [InlineData(3969, 63, 0xF5030A1FDF3C407BUL)] // case 63
    [InlineData(4096, 64, 0x39069AB022ABF776UL)] // case 64
    [InlineData(4225, 65, 0x626B3525C640CC96UL)] // case 65
    [InlineData(6400, 80, 0x175CA510572CCF26UL)] // case 80
    [InlineData(9025, 95, 0x588B618F20469590UL)] // case 95
    [InlineData(9216, 96, 0x3EEE7EC1E5592EB3UL)] // case 96
    [InlineData(9409, 97, 0xFCF0DC0DA9DF5E16UL)] // case 97
    [InlineData(10000, 100, 0x05AD36F677825CE0UL)] // case 100
    [InlineData(14884, 122, 0xA3693D5D4C5949C0UL)] // case 122
    [InlineData(57121, 239, 0x4BEC2A224880C794UL)] // case 239
    [InlineData(57600, 240, 0x136969EED9B76A41UL)] // case 240
    [InlineData(58081, 241, 0x416BCDDAC2720631UL)] // case 241
    [InlineData(65025, 255, 0x74FBCE74D2FE60F8UL)] // case 255
    [InlineData(65536, 256, 0x7FD20F1452DFBC03UL)] // case 256
    [InlineData(66049, 257, 0x6579174D69470023UL)] // case 257
    [InlineData(66564, 258, 0xEEEB799A0CDEA491UL)] // case 258
    [InlineData(88804, 298, 0xEA5E4337205827A5UL)] // case 298
    [InlineData(0, 299, 0x58F5C1A920F6BC85UL)] // case 299
    [InlineData(0, 341, 0xF72FF7CEB26FCB0DUL)] // case 300
    [InlineData(0, 389, 0x7C7CC0416808AECAUL)] // case 301
    [InlineData(0, 507, 0xE5229D5C4C0D865BUL)] // case 303
    [InlineData(0, 661, 0xAABA8A5EDEB2DFE2UL)] // case 305
    [InlineData(0, 985, 0xF909778BA8848DD7UL)] // case 308
    [InlineData(0, 1125, 0xB170D0B9734B28F9UL)] // case 309
    [InlineData(0, 2501, 0xDB3B816B358D908EUL)] // case 315
    [InlineData(0, 4265, 0xBD39EE8F95D0E05AUL)] // case 319
    [InlineData(0, 16205, 0xC1239E0BEFE5AF41UL)] // case 329
    [InlineData(0, 70388, 0x7E7F95AB48316912UL)] // case 340
    [InlineData(0, 1048576, 0x090DF4AA8E1FF180UL)] // case 361 (last)
    public void GoogleSelfTestVectors(int offset, int length, ulong expected)
    {
        var input = SelfTestData.AsSpan(offset, length);
        Assert.Equal(expected, FarmHash.Hash64(input));

        var farm = default(FarmHash);
        farm.Append(input);
        Assert.Equal(expected, farm.FinalizeHash());

        // Unaligned, uneven chunks.
        farm.Reset();
        for (var i = 0; i < length; i += 97)
        {
            farm.Append(input.Slice(i, Math.Min(97, length - i)));
        }

        Assert.Equal(expected, farm.FinalizeHash());
    }

    [Fact]
    public void Empty()
    {
        var farm = default(FarmHash);

        Assert.Equal(FarmHash.Hash64(ReadOnlySpan<byte>.Empty), farm.FinalizeHash());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(95)]
    [InlineData(96)]
    [InlineData(97)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(191)]
    [InlineData(192)]
    [InlineData(193)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(258)]
    [InlineData(319)]
    [InlineData(320)]
    [InlineData(321)]
    [InlineData(383)]
    [InlineData(384)]
    [InlineData(385)]
    [InlineData(511)]
    [InlineData(512)]
    [InlineData(513)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void AppendSingleBlock(int length)
    {
        var data = CreateData(length);
        var expected = FarmHash.Hash64(data);

        var farm = default(FarmHash);
        farm.Append(data);

        Assert.Equal(expected, farm.FinalizeHash());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(320)]
    [InlineData(321)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void AppendOneByteAtATime(int length)
    {
        var data = CreateData(length);
        var expected = FarmHash.Hash64(data);

        var farm = default(FarmHash);
        for (var i = 0; i < data.Length; i++)
        {
            farm.Append(data.AsSpan(i, 1));
        }

        Assert.Equal(expected, farm.FinalizeHash());
    }

    [Theory]
    [InlineData(257, 1)]
    [InlineData(257, 63)]
    [InlineData(257, 64)]
    [InlineData(257, 128)]
    [InlineData(257, 255)]
    [InlineData(257, 256)]
    [InlineData(320, 64)]
    [InlineData(320, 255)]
    [InlineData(320, 256)]
    [InlineData(321, 1)]
    [InlineData(321, 64)]
    [InlineData(321, 255)]
    [InlineData(321, 256)]
    [InlineData(321, 257)]
    [InlineData(512, 256)]
    [InlineData(1024, 256)]
    public void AppendTwoBlocks(int length, int split)
    {
        var data = CreateData(length);
        var expected = FarmHash.Hash64(data);

        var farm = default(FarmHash);
        farm.Append(data.AsSpan(0, split));
        farm.Append(data.AsSpan(split));

        Assert.Equal(expected, farm.FinalizeHash());
    }

    [Theory]
    [InlineData(257)]
    [InlineData(258)]
    [InlineData(319)]
    [InlineData(320)]
    [InlineData(321)]
    [InlineData(383)]
    [InlineData(384)]
    [InlineData(385)]
    [InlineData(511)]
    [InlineData(512)]
    [InlineData(513)]
    [InlineData(1024)]
    public void EveryPossibleTwoWaySplit(int length)
    {
        var data = CreateData(length);
        var expected = FarmHash.Hash64(data);

        for (var split = 0; split <= length; split++)
        {
            var farm = default(FarmHash);
            farm.Append(data.AsSpan(0, split));
            farm.Append(data.AsSpan(split));

            Assert.Equal(expected, farm.FinalizeHash());
        }
    }

    [Theory]
    [InlineData(257)]
    [InlineData(320)]
    [InlineData(321)]
    [InlineData(512)]
    [InlineData(1024)]
    public void VariousChunkSizes(int length)
    {
        var data = CreateData(length);
        var expected = FarmHash.Hash64(data);

        for (var chunkSize = 1; chunkSize <= 129; chunkSize++)
        {
            var farm = default(FarmHash);

            for (var offset = 0; offset < data.Length;)
            {
                var count = Math.Min(chunkSize, data.Length - offset);
                farm.Append(data.AsSpan(offset, count));
                offset += count;
            }

            Assert.Equal(expected, farm.FinalizeHash());
        }
    }

    [Fact]
    public void RandomChunkSizes()
    {
        const int length = 100_000;
        var data = CreateData(length);
        var expected = FarmHash.Hash64(data);

        for (var iteration = 0; iteration < 100; iteration++)
        {
            var random = new Random(iteration);
            var farm = default(FarmHash);
            var offset = 0;

            while (offset < data.Length)
            {
                var count = Math.Min(random.Next(1, 1025), data.Length - offset);
                farm.Append(data.AsSpan(offset, count));
                offset += count;
            }

            Assert.Equal(expected, farm.FinalizeHash());
        }
    }

    [Fact]
    public void EmptyAppendDoesNotChangeHash()
    {
        var data = CreateData(1000);
        var expected = FarmHash.Hash64(data);

        var farm = default(FarmHash);
        farm.Append(data.AsSpan(0, 200));
        farm.Append(ReadOnlySpan<byte>.Empty);
        farm.Append(data.AsSpan(200));
        farm.Append(ReadOnlySpan<byte>.Empty);

        Assert.Equal(expected, farm.FinalizeHash());
    }

    [Fact]
    public void FinalizeCanBeCalledMultipleTimes()
    {
        var data = CreateData(1000);

        var farm = default(FarmHash);
        farm.Append(data);

        var hash1 = farm.FinalizeHash();
        var hash2 = farm.FinalizeHash();

        Assert.Equal(hash1, hash2);
        Assert.Equal(FarmHash.Hash64(data), hash1);
    }

    [Fact]
    public void AppendAfterFinalizeContinuesHash()
    {
        var data1 = CreateData(300);
        var data2 = CreateData(500, 123);

        var combined = new byte[data1.Length + data2.Length];
        data1.CopyTo(combined, 0);
        data2.CopyTo(combined, data1.Length);

        var farm = default(FarmHash);
        farm.Append(data1);
        _ = farm.FinalizeHash();
        farm.Append(data2);

        Assert.Equal(FarmHash.Hash64(combined), farm.FinalizeHash());
    }

    [Fact]
    public void InitializeResetsSmallInput()
    {
        var first = CreateData(100);
        var second = CreateData(200, 123);

        var farm = default(FarmHash);
        farm.Append(first);
        _ = farm.FinalizeHash();

        farm.Reset();
        farm.Append(second);

        Assert.Equal(FarmHash.Hash64(second), farm.FinalizeHash());
    }

    [Fact]
    public void InitializeResetsBlockPhase()
    {
        var first = CreateData(1000);
        var second = CreateData(700, 123);

        var farm = default(FarmHash);
        farm.Append(first);
        _ = farm.FinalizeHash();

        farm.Reset();
        farm.Append(second);

        Assert.Equal(FarmHash.Hash64(second), farm.FinalizeHash());
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("abc")]
    [InlineData("Hello, world!")]
    [InlineData("日本語のテスト")]
    [InlineData("🌸🍣🚀")]
    public void CharSpan(string text)
    {
        var farm = default(FarmHash);
        farm.Append(text.AsSpan());

        Assert.Equal(FarmHash.Hash64(text), farm.FinalizeHash());
        Assert.Equal(FarmHash.Hash64(text.AsSpan()), farm.FinalizeHash());
    }

    [Fact]
    public void CharSpanMultipleAppends()
    {
        const string a = "Hello, ";
        const string b = "世界";
        const string c = "🌸!";
        const string combined = a + b + c;

        var farm = default(FarmHash);
        farm.Append(a.AsSpan());
        farm.Append(b.AsSpan());
        farm.Append(c.AsSpan());

        Assert.Equal(FarmHash.Hash64(combined), farm.FinalizeHash());
    }

    [Fact]
    public void DifferentInputProducesDifferentHashes()
    {
        var a = CreateData(1000);
        var b = CreateData(1000);
        b[500] ^= 0x80;

        Assert.NotEqual(FarmHash.Hash64(a), FarmHash.Hash64(b));
    }

    [Fact]
    public void StringHashesRawUtf16Bytes()
    {
        const string text = "Hello, 世界🌸";
        var expected = FarmHash.Hash64(System.Runtime.InteropServices.MemoryMarshal.AsBytes(text.AsSpan()));
        Assert.Equal(expected, FarmHash.Hash64(text));
        Assert.Equal(expected, FarmHash.Hash64(text.AsSpan()));
        Assert.NotEqual(FarmHash.Hash64(System.Text.Encoding.UTF8.GetBytes(text)), FarmHash.Hash64(text));

        // A null string is hashed as empty.
        Assert.Equal(FarmHash.Hash64(ReadOnlySpan<byte>.Empty), FarmHash.Hash64((string)null!));
    }

    private static byte[] CreateSelfTestData()
    {// Setup() in farmhash.cc: kDataSize = 1 << 20, a = 9, b = 777.
        const ulong K0 = 0xc3a5c85c97cb3127UL;
        var data = new byte[1 << 20];
        ulong a = 9;
        ulong b = 777;
        for (var i = 0; i < data.Length; i++)
        {
            unchecked
            {
                a += b;
                b += a;
                a = (a ^ (a >> 41)) * K0;
                b = ((b ^ (b >> 41)) * K0) + (ulong)i;
                data[i] = (byte)(b >> 37);
            }
        }

        return data;
    }

    private static byte[] CreateData(int length, int seed = 0)
    {
        var data = new byte[length];
        var state = unchecked((uint)(0x9e3779b9 + seed));

        for (var i = 0; i < data.Length; i++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            data[i] = (byte)state;
        }

        return data;
    }
}
