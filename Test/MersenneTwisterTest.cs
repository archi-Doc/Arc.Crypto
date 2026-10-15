// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class MersenneTwisterTest
{
    [Fact]
    public void Test1()
    {
        var init = new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL };
        var mt = new MersenneTwister(init);

        // NextULong test
        mt.NextUInt64().Is(7266447313870364031UL);
        mt.NextUInt64().Is(4946485549665804864UL);
        mt.NextUInt64().Is(16945909448695747420UL);
        mt.NextUInt64().Is(16394063075524226720UL);
        mt.NextUInt64().Is(4873882236456199058UL);

        for (var i = 0; i < 990; i++)
        {
            mt.NextUInt64();
        }

        mt.NextUInt64().Is(10197035660403006684UL);
        mt.NextUInt64().Is(13004818533162292132UL);
        mt.NextUInt64().Is(9831652587047067687UL);
        mt.NextUInt64().Is(7619315254749630976UL);
        mt.NextUInt64().Is(994412663058993407UL);

        // NextDouble test
        DoubleToString(mt.NextDouble()).Is("0.35252031");
        DoubleToString(mt.NextDouble()).Is("0.51052342");
        DoubleToString(mt.NextDouble()).Is("0.79771733");
        DoubleToString(mt.NextDouble()).Is("0.39300273");
        DoubleToString(mt.NextDouble()).Is("0.27216673");

        string DoubleToString(double d) => d.ToString("F8");

        // Reset(byte[]) test
        var size = init.Length * sizeof(ulong);
        byte[] seed = new byte[size];
        Buffer.BlockCopy(init, 0, seed, 0, size);
        mt.Reset(seed);

        mt.NextUInt64().Is(7266447313870364031UL);
        mt.NextUInt64().Is(4946485549665804864UL);
        mt.NextUInt64().Is(16945909448695747420UL);
        mt.NextUInt64().Is(16394063075524226720UL);
        mt.NextUInt64().Is(4873882236456199058UL);

        // NextBytes test
        var bytes = new byte[24];
        var bytes2 = new byte[24];
        var span = bytes.AsSpan();
        BitConverter.TryWriteBytes(span, 7266447313870364031UL);
        span = span.Slice(8);
        BitConverter.TryWriteBytes(span, 4946485549665804864UL);
        span = span.Slice(8);
        BitConverter.TryWriteBytes(span, 16945909448695747420UL);

        for (var i = 0; i <= 8; i++)
        {
            mt.Reset(init);
            var span2 = bytes2.AsSpan(0, 16 + i);
            mt.NextBytes(span2);
            span2.SequenceEqual(bytes.AsSpan().Slice(0, 16 + i)).IsTrue();
        }
    }

    [Fact]
    public void InitByArrayMatchesReferenceOutput()
    {
        // mt19937-64.out.txt (https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/mt19937-64.out.txt):
        // 1000 outputs of genrand64_int64() followed by 1000 outputs of genrand64_real2() after
        // init_by_array64({ 0x12345, 0x23456, 0x34567, 0x45678 }).
        // The wrapping sum and the XOR are computed over all 1000 genrand64_int64() values of that file.
        var mt = new MersenneTwister(new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL });
        var values = new ulong[1000];
        for (var i = 0; i < values.Length; i++)
        {
            values[i] = mt.NextUInt64();
        }

        values[5].Is(14877448043947020171UL);
        values[6].Is(6740343660852211943UL);
        values[7].Is(13857871200353263164UL);
        values[8].Is(5249110015610582907UL);
        values[9].Is(10205081126064480383UL);
        values[495].Is(15121667220761532906UL);
        values[499].Is(3448088038819200619UL);
        values[500].Is(3692020001240358871UL);
        values[995].Is(10197035660403006684UL);

        ulong sum = 0;
        ulong xor = 0;
        foreach (var x in values)
        {
            sum += x;
            xor ^= x;
        }

        sum.Is(11516885302434052501UL);
        xor.Is(15208572878667951965UL);

        for (var i = 0; i < 995; i++)
        {
            mt.NextDouble();
        }

        mt.NextDouble().ToString("F8").Is("0.82342139");
        mt.NextDouble().ToString("F8").Is("0.83003381");
        mt.NextDouble().ToString("F8").Is("0.53571829");
        mt.NextDouble().ToString("F8").Is("0.41081533");
        mt.NextDouble().ToString("F8").Is("0.48600142");
    }

    [Fact]
    public void SingleSeedMatchesStdMt19937_64()
    {
        // C++ [rand.predef]: the 10000th consecutive invocation of a default-constructed std::mt19937_64
        // (init_genrand64(5489)) produces 9981545732273789042.
        // The first three values were computed with a port of mt19937-64.c that reproduces mt19937-64.out.txt.
        var mt = new MersenneTwister(5489UL);
        mt.NextUInt64().Is(14514284786278117030UL);
        mt.NextUInt64().Is(4620546740167642908UL);
        mt.NextUInt64().Is(13109570281517897720UL);
        for (var i = 3; i < 9999; i++)
        {
            mt.NextUInt64();
        }

        mt.NextUInt64().Is(9981545732273789042UL);

        // Reset(ulong) restarts the sequence on a used instance.
        mt.Reset(5489UL);
        mt.NextUInt64().Is(14514284786278117030UL);

        // The uint overload widens the seed and gives the same sequence as the ulong overload.
        var mt32 = new MersenneTwister(5489U);
        mt32.NextUInt64().Is(14514284786278117030UL);
        mt32.NextUInt64().Is(4620546740167642908UL);
        new MersenneTwister(uint.MaxValue).NextUInt64().Is(3814183646661098318UL);
        new MersenneTwister((ulong)uint.MaxValue).NextUInt64().Is(3814183646661098318UL);
    }

    [Fact]
    public void SeedArraysLongerThanStateAreFullyUsed()
    {
        // init_by_array64 runs max(312, length) mixing steps, so seed words past index 311 still matter.
        // Expected values were computed with a port of mt19937-64.c that reproduces mt19937-64.out.txt.
        var seeds = Enumerable.Range(1, 400).Select(x => (ulong)x).ToArray();
        var mt = new MersenneTwister(seeds);
        mt.NextUInt64().Is(1036238305513982027UL);
        mt.NextUInt64().Is(8421852567675961574UL);

        var changed = (ulong[])seeds.Clone();
        changed[399] ^= 1;
        new MersenneTwister(changed).NextUInt64().Is(4858633532706871481UL);

        // Reset(byte[]) on a used instance reads the same words in native byte order.
        mt.Reset(MemoryMarshal.AsBytes(seeds.AsSpan()).ToArray());
        mt.NextUInt64().Is(1036238305513982027UL);
        mt.Reset(seeds);
        mt.NextUInt64().Is(1036238305513982027UL);
    }

    [Fact]
    public void DefaultConstructorUsesRandomSeed()
    {
        // A collision of two independent 64-bit outputs has probability 2^-64.
        var a = new MersenneTwister();
        var b = new MersenneTwister();
        a.NextUInt64().IsNot(b.NextUInt64());
    }

    [Fact]
    public void NextBytesMatchesBaseAlgorithm()
    {
        // NextBytes is overridden for speed and must produce exactly what RandomUInt64Base.NextBytes produces
        // from NextUInt64: successive values in native byte order, with a partial final word consuming a whole value.
        var seed = new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL };
        foreach (var skip in new[] { 0, 1, 310, 311 })
        {// Start at different positions within the 312-word state.
            for (var length = 0; length <= 64; length++)
            {
                foreach (var offset in new[] { 1, 3, 7 })
                {
                    Check(skip, length, offset);
                }
            }

            Check(skip, 2501, 1); // Crosses a state regeneration.
        }

        void Check(int skip, int length, int offset)
        {
            var mt = new MersenneTwister(seed);
            var baseline = new BaseNextBytes(new MersenneTwister(seed));
            var reference = new MersenneTwister(seed);
            for (var i = 0; i < skip; i++)
            {
                mt.NextUInt64();
                baseline.NextUInt64();
                reference.NextUInt64();
            }

            var words = new ulong[(length + 7) / 8];
            for (var i = 0; i < words.Length; i++)
            {
                words[i] = reference.NextUInt64();
            }

            var output = Enumerable.Repeat((byte)0xA5, length + offset + 1).ToArray();
            var expected = Enumerable.Repeat((byte)0xA5, length + offset + 1).ToArray();
            mt.NextBytes(output.AsSpan(offset, length));
            baseline.NextBytes(expected.AsSpan(offset, length));

            output.AsSpan().SequenceEqual(expected).IsTrue();
            output.AsSpan(offset, length).SequenceEqual(MemoryMarshal.AsBytes(words.AsSpan()).Slice(0, length)).IsTrue();
            output.AsSpan(0, offset).ToArray().All(x => x == 0xA5).IsTrue();
            output[^1].Is((byte)0xA5);

            var next = reference.NextUInt64();
            mt.NextUInt64().Is(next);
            baseline.NextUInt64().Is(next);
        }
    }

    /// <summary>
    /// Forwards NextUInt64 and keeps the NextBytes implementation of <see cref="RandomUInt64Base"/>.
    /// </summary>
    private sealed class BaseNextBytes(RandomUInt64Base inner) : RandomUInt64Base
    {
        public override ulong NextUInt64() => inner.NextUInt64();
    }
}
