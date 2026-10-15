// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class RandomUInt64BaseTest
{
    [Fact]
    public void BoundedInt32UsesTopBitsAndRejectsOutOfRangeDraws()
    {
        // NextInt32(5) uses the top 3 bits: 7 and 5 are rejected and redrawn (no modulo reduction), 4 is accepted.
        var r = new ScriptedRandom(0xE000000000000000, 0xA000000000000000, 0x8000000000000000);
        r.NextInt32(5).Is(4);
        r.Draws.Is(3);

        // Low bits are ignored.
        r = new ScriptedRandom(0x1FFFFFFFFFFFFFFF);
        r.NextInt32(5).Is(0);
        r.Draws.Is(1);

        // [0, int.MaxValue): 31 bits, the all-ones draw equals maxValue and is rejected.
        r = new ScriptedRandom(ulong.MaxValue, 0xFFFFFFFC_00000000);
        r.NextInt32(int.MaxValue).Is(int.MaxValue - 1);
        r.Draws.Is(2);

        // [int.MinValue, int.MaxValue): the result wraps from the unsigned offset to the top of the range.
        r = new ScriptedRandom(ulong.MaxValue, 0xFFFFFFFE_00000000);
        r.NextInt32(int.MinValue, int.MaxValue).Is(int.MaxValue - 1);
        r.Draws.Is(2);
        new ScriptedRandom(0).NextInt32(int.MinValue, int.MaxValue).Is(int.MinValue);

        // Negative ranges.
        r = new ScriptedRandom(ulong.MaxValue);
        r.NextInt32(-3, -1).Is(-2);
        r.Draws.Is(1);
        r = new ScriptedRandom(ulong.MaxValue, 0x7FFFFFFFFFFFFFFF);
        r.NextInt32(-3, 0).Is(-2);
        r.Draws.Is(2);
    }

    [Fact]
    public void BoundedInt64UsesTopBitsAndRejectsOutOfRangeDraws()
    {
        // [0, long.MaxValue): 63 bits.
        var r = new ScriptedRandom(ulong.MaxValue, ulong.MaxValue - 2);
        r.NextInt64(long.MaxValue).Is(long.MaxValue - 1);
        r.Draws.Is(2);

        // [long.MinValue, long.MaxValue): 64 bits, only ulong.MaxValue is out of range.
        r = new ScriptedRandom(ulong.MaxValue, ulong.MaxValue - 1);
        r.NextInt64(long.MinValue, long.MaxValue).Is(long.MaxValue - 1);
        r.Draws.Is(2);
        new ScriptedRandom(0).NextInt64(long.MinValue, long.MaxValue).Is(long.MinValue);
        new ScriptedRandom(1UL << 63).NextInt64(long.MinValue, long.MaxValue).Is(0);

        // [-3, 0): 2 bits, 3 is rejected.
        r = new ScriptedRandom(ulong.MaxValue, 0x4000000000000000);
        r.NextInt64(-3, 0).Is(-2);
        r.Draws.Is(2);

        // NextInt64(5): same rejection as the 32-bit overload.
        r = new ScriptedRandom(0xE000000000000000, 0xA000000000000000, 0x8000000000000000);
        r.NextInt64(5).Is(4);
        r.Draws.Is(3);
    }

    [Fact]
    public void BoundedValuesCoverTheWholeRange()
    {
        var random = new Xoshiro256StarStar(42);
        var seen32 = new bool[13];
        var seen64 = new bool[13];
        for (var i = 0; i < 10_000; i++)
        {
            var x = random.NextInt32(13);
            Assert.InRange(x, 0, 12);
            seen32[x] = true;

            var y = random.NextInt64(-6, 7);
            Assert.InRange(y, -6, 6);
            seen64[y + 6] = true;
        }

        seen32.All(x => x).IsTrue();
        seen64.All(x => x).IsTrue();
    }

    [Fact]
    public void NextBytesWritesWordsInNativeByteOrder()
    {
        // The base NextBytes writes each NextUInt64 value in native byte order and fills a 1-7 byte tail
        // from the first bytes of one more value. The expectation is built with MemoryMarshal, so it holds on any endianness.
        for (var length = 0; length <= 40; length++)
        {
            foreach (var offset in new[] { 0, 1, 3 })
            {
                var words = new ulong[(length + 7) / 8];
                var random = new ScriptedRandom();
                for (var i = 0; i < words.Length; i++)
                {
                    words[i] = 0x0102030405060708UL * (ulong)(i + 1);
                    random.Values.Add(words[i]);
                }

                var output = new byte[length + offset + 1];
                output.AsSpan().Fill(0xA5);
                random.NextBytes(output.AsSpan(offset, length));

                output.AsSpan(offset, length).SequenceEqual(MemoryMarshal.AsBytes(words.AsSpan()).Slice(0, length)).IsTrue();
                output.AsSpan(0, offset).ToArray().All(x => x == 0xA5).IsTrue();
                output[^1].Is((byte)0xA5);
                random.Draws.Is(words.Length);
            }
        }
    }

    private sealed class ScriptedRandom(params ulong[] values) : RandomUInt64Base
    {
        public List<ulong> Values { get; } = [.. values];

        public int Draws { get; private set; }

        public override ulong NextUInt64() => this.Values[this.Draws++];
    }
}
