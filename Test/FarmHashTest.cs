// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using Xunit;

namespace XunitTest;

public class FarmHashTest
{
    [Fact]
    public void Empty()
    {
        var farm = default(FarmHash3);

        Assert.Equal(FarmHash3.Hash64(ReadOnlySpan<byte>.Empty), farm.Finalize());
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
        var expected = FarmHash3.Hash64(data);

        var farm = default(FarmHash3);
        farm.Append(data);

        Assert.Equal(expected, farm.Finalize());
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
        var expected = FarmHash3.Hash64(data);

        var farm = default(FarmHash3);
        for (var i = 0; i < data.Length; i++)
        {
            farm.Append(data.AsSpan(i, 1));
        }

        Assert.Equal(expected, farm.Finalize());
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
        var expected = FarmHash3.Hash64(data);

        var farm = default(FarmHash3);
        farm.Append(data.AsSpan(0, split));
        farm.Append(data.AsSpan(split));

        Assert.Equal(expected, farm.Finalize());
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
        var expected = FarmHash3.Hash64(data);

        for (var split = 0; split <= length; split++)
        {
            var farm = default(FarmHash3);
            farm.Append(data.AsSpan(0, split));
            farm.Append(data.AsSpan(split));

            Assert.Equal(expected, farm.Finalize());
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
        var expected = FarmHash3.Hash64(data);

        for (var chunkSize = 1; chunkSize <= 129; chunkSize++)
        {
            var farm = default(FarmHash3);

            for (var offset = 0; offset < data.Length;)
            {
                var count = Math.Min(chunkSize, data.Length - offset);
                farm.Append(data.AsSpan(offset, count));
                offset += count;
            }

            Assert.Equal(expected, farm.Finalize());
        }
    }

    [Fact]
    public void RandomChunkSizes()
    {
        const int length = 100_000;
        var data = CreateData(length);
        var expected = FarmHash3.Hash64(data);

        for (var iteration = 0; iteration < 100; iteration++)
        {
            var random = new Random(iteration);
            var farm = default(FarmHash3);
            var offset = 0;

            while (offset < data.Length)
            {
                var count = Math.Min(random.Next(1, 1025), data.Length - offset);
                farm.Append(data.AsSpan(offset, count));
                offset += count;
            }

            Assert.Equal(expected, farm.Finalize());
        }
    }

    [Fact]
    public void EmptyAppendDoesNotChangeHash()
    {
        var data = CreateData(1000);
        var expected = FarmHash3.Hash64(data);

        var farm = default(FarmHash3);
        farm.Append(data.AsSpan(0, 200));
        farm.Append(ReadOnlySpan<byte>.Empty);
        farm.Append(data.AsSpan(200));
        farm.Append(ReadOnlySpan<byte>.Empty);

        Assert.Equal(expected, farm.Finalize());
    }

    [Fact]
    public void FinalizeCanBeCalledMultipleTimes()
    {
        var data = CreateData(1000);

        var farm = default(FarmHash3);
        farm.Append(data);

        var hash1 = farm.Finalize();
        var hash2 = farm.Finalize();

        Assert.Equal(hash1, hash2);
        Assert.Equal(FarmHash3.Hash64(data), hash1);
    }

    [Fact]
    public void AppendAfterFinalizeContinuesHash()
    {
        var data1 = CreateData(300);
        var data2 = CreateData(500, 123);

        var combined = new byte[data1.Length + data2.Length];
        data1.CopyTo(combined, 0);
        data2.CopyTo(combined, data1.Length);

        var farm = default(FarmHash3);
        farm.Append(data1);
        _ = farm.Finalize();
        farm.Append(data2);

        Assert.Equal(FarmHash3.Hash64(combined), farm.Finalize());
    }

    [Fact]
    public void InitializeResetsSmallInput()
    {
        var first = CreateData(100);
        var second = CreateData(200, 123);

        var farm = default(FarmHash3);
        farm.Append(first);
        _ = farm.Finalize();

        farm.Initialize();
        farm.Append(second);

        Assert.Equal(FarmHash3.Hash64(second), farm.Finalize());
    }

    [Fact]
    public void InitializeResetsBlockPhase()
    {
        var first = CreateData(1000);
        var second = CreateData(700, 123);

        var farm = default(FarmHash3);
        farm.Append(first);
        _ = farm.Finalize();

        farm.Initialize();
        farm.Append(second);

        Assert.Equal(FarmHash3.Hash64(second), farm.Finalize());
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
        var farm = default(FarmHash3);
        farm.Append(text.AsSpan());

        Assert.Equal(FarmHash3.Hash64(text), farm.Finalize());
        Assert.Equal(FarmHash3.Hash64(text.AsSpan()), farm.Finalize());
    }

    [Fact]
    public void CharSpanMultipleAppends()
    {
        const string a = "Hello, ";
        const string b = "世界";
        const string c = "🌸!";
        const string combined = a + b + c;

        var farm = default(FarmHash3);
        farm.Append(a.AsSpan());
        farm.Append(b.AsSpan());
        farm.Append(c.AsSpan());

        Assert.Equal(FarmHash3.Hash64(combined), farm.Finalize());
    }

    [Fact]
    public void DifferentInputProducesDifferentHashes()
    {
        var a = CreateData(1000);
        var b = CreateData(1000);
        b[500] ^= 0x80;

        Assert.NotEqual(FarmHash3.Hash64(a), FarmHash3.Hash64(b));
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
