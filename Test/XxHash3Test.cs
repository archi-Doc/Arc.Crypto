// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Linq;
using System.Runtime.InteropServices;
using Xunit;

namespace Test;

/// <summary>
/// Tests <see cref="Arc.Crypto.XxHash3"/> against System.IO.Hashing.XxHash3.
/// </summary>
public class XxHash3Test
{
    private static readonly byte[] Data = CreateData();

    public static TheoryData<long> Seeds => new() { 0L, 1L, -1L, 0x0123456789ABCDEFL, long.MinValue, };

    [Theory]
    [MemberData(nameof(Seeds))]
    public void OneShotMatchesSystemIOHashing(long seed)
    {
        // 0-16, 17-128, 129-240, over 240 (one block), and several 1024-byte blocks with a seed-derived secret.
        foreach (var length in Enumerable.Range(0, 1101).Concat([2047, 2048, 2049, 3072, 3073, 4096, 4500]))
        {
            var span = Data.AsSpan(0, length);
            Arc.Crypto.XxHash3.Hash64(span, seed).Is(System.IO.Hashing.XxHash3.HashToUInt64(span, seed));
        }

        // Unaligned input.
        for (var offset = 1; offset < 8; offset++)
        {
            foreach (var length in new[] { 3, 8, 16, 100, 200, 241, 1500, })
            {
                var span = Data.AsSpan(offset, length);
                Arc.Crypto.XxHash3.Hash64(span, seed).Is(System.IO.Hashing.XxHash3.HashToUInt64(span, seed));
            }
        }
    }

    [Theory]
    [MemberData(nameof(Seeds))]
    public void PrecomputedSecretMatchesSystemIOHashing(long seed)
    {// The internal overload used by the string comparers must give the same value as the seeded hash.
        var secret = Arc.Crypto.XxHash3.CreateSecret(seed);
        foreach (var length in new[] { 0, 1, 16, 17, 128, 129, 240, 241, 255, 256, 1024, 1025, 2048, 4500, })
        {
            var span = Data.AsSpan(1, length);
            Arc.Crypto.XxHash3.Hash64(span, seed, secret).Is(System.IO.Hashing.XxHash3.HashToUInt64(span, seed));
        }
    }

    [Theory]
    [MemberData(nameof(Seeds))]
    public void StreamingMatchesSystemIOHashing(long seed)
    {
        int[] lengths = [0, 1, 16, 17, 128, 129, 240, 241, 255, 256, 257, 300, 511, 512, 513, 1023, 1024, 1025, 1088, 2048, 2049, 4097, 4500];
        int[] chunks = [1, 7, 63, 64, 65, 192, 255, 256, 257, 1023, 1024, 1025, 5000];
        foreach (var length in lengths)
        {
            foreach (var chunk in chunks)
            {
                var arc = new Arc.Crypto.XxHash3(seed);
                var sys = new System.IO.Hashing.XxHash3(seed);
                for (var i = 0; i < length; i += chunk)
                {
                    var c = Data.AsSpan(i, Math.Min(chunk, length - i));
                    arc.Append(c);
                    sys.Append(c);

                    // GetCurrentHashAsUInt64 must not modify the state, so it is called after every Append.
                    arc.GetCurrentHashAsUInt64().Is(sys.GetCurrentHashAsUInt64());
                }

                var expected = System.IO.Hashing.XxHash3.HashToUInt64(Data.AsSpan(0, length), seed);
                arc.GetCurrentHashAsUInt64().Is(expected);
                arc.GetCurrentHashAsUInt64().Is(Arc.Crypto.XxHash3.Hash64(Data.AsSpan(0, length), seed));

                // Reset keeps the seed.
                arc.Reset();
                arc.Append(Data.AsSpan(0, 300));
                arc.GetCurrentHashAsUInt64().Is(System.IO.Hashing.XxHash3.HashToUInt64(Data.AsSpan(0, 300), seed));
            }
        }
    }

    [Fact]
    public void StreamingRandomChunksMatchSystemIOHashing()
    {
        for (var iteration = 0; iteration < 200; iteration++)
        {
            var random = new Random(iteration);
            var seed = iteration % 2 == 0 ? 0 : random.NextInt64(long.MinValue, long.MaxValue);
            var length = random.Next(0, Data.Length + 1);
            var arc = new Arc.Crypto.XxHash3(seed);
            var position = 0;
            while (position < length)
            {
                var size = Math.Min(random.Next(0, 2001), length - position); // Includes empty appends.
                arc.Append(Data.AsSpan(position, size));
                position += size;
            }

            arc.GetCurrentHashAsUInt64().Is(System.IO.Hashing.XxHash3.HashToUInt64(Data.AsSpan(0, length), seed));
        }
    }

    [Fact]
    public void Constructors()
    {
        var empty = System.IO.Hashing.XxHash3.HashToUInt64(ReadOnlySpan<byte>.Empty);
        new Arc.Crypto.XxHash3().GetCurrentHashAsUInt64().Is(empty);
        new Arc.Crypto.XxHash3(0).GetCurrentHashAsUInt64().Is(empty);
        new Arc.Crypto.XxHash3(42).GetCurrentHashAsUInt64().Is(System.IO.Hashing.XxHash3.HashToUInt64(ReadOnlySpan<byte>.Empty, 42));
    }

    [Fact]
    public void ByteOverloadsWriteBigEndian()
    {
        foreach (var length in new[] { 0, 5, 100, 300, 2000, })
        {
            var source = Data.AsSpan(0, length).ToArray();
            Assert.Equal(System.IO.Hashing.XxHash3.Hash(source), Arc.Crypto.XxHash3.Hash(source));
            Assert.Equal(System.IO.Hashing.XxHash3.Hash(source, 42), Arc.Crypto.XxHash3.Hash(source, 42));
            Assert.Equal(System.IO.Hashing.XxHash3.Hash((ReadOnlySpan<byte>)source, 42), Arc.Crypto.XxHash3.Hash((ReadOnlySpan<byte>)source, 42));
            Assert.Equal(System.IO.Hashing.XxHash3.Hash((ReadOnlySpan<byte>)source), Arc.Crypto.XxHash3.Hash((ReadOnlySpan<byte>)source));

            // The value is written in big-endian byte order.
            var value = Arc.Crypto.XxHash3.Hash64(source, 42);
            Assert.Equal(value, System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(Arc.Crypto.XxHash3.Hash(source, 42)));

            // Only the first 8 bytes of a larger destination are written.
            var destination = Enumerable.Repeat((byte)0xAA, 10).ToArray();
            Arc.Crypto.XxHash3.Hash(source, destination, 42).Is(Arc.Crypto.XxHash3.HashLength);
            Assert.Equal(System.IO.Hashing.XxHash3.Hash(source, 42), destination[..8]);
            Assert.Equal(new byte[] { 0xAA, 0xAA, }, destination[8..]);

            Arc.Crypto.XxHash3.Hash(source, destination).Is(Arc.Crypto.XxHash3.HashLength);
            Assert.Equal(System.IO.Hashing.XxHash3.Hash(source), destination[..8]);
        }
    }

    [Fact]
    public void ArgumentValidation()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Arc.Crypto.XxHash3.Hash(Data, new byte[7]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Arc.Crypto.XxHash3.Hash(Data, Span<byte>.Empty, 1));
        Assert.Throws<ArgumentNullException>(() => Arc.Crypto.XxHash3.Hash((byte[])null!));
        Assert.Throws<ArgumentNullException>(() => Arc.Crypto.XxHash3.Hash((byte[])null!, 1));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("hello")]
    [InlineData("日本語のテスト🌸🍣🚀 and a longer tail that exceeds sixteen characters")]
    public void StringOverloadsHashRawUtf16Bytes(string text)
    {
        var expected = System.IO.Hashing.XxHash3.HashToUInt64(MemoryMarshal.AsBytes(text.AsSpan()));
        Arc.Crypto.XxHash3.Hash64(text).Is(expected);
        Arc.Crypto.XxHash3.Hash64(text.AsSpan()).Is(expected);
    }

    [Fact]
    public void NullStringIsEmpty()
    {
        Arc.Crypto.XxHash3.Hash64((string)null!).Is(System.IO.Hashing.XxHash3.HashToUInt64(ReadOnlySpan<byte>.Empty));
    }

    private static byte[] CreateData()
    {
        var data = new byte[5000];
        new Random(1).NextBytes(data);
        return data;
    }
}
