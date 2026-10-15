// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Xoroshiro128StarStarTest
{
    private const int Length = 1023;
    private const int Length2 = 1024;

    [Fact]
    public void Test1()
    {
        var xo = new Xoroshiro128StarStar(43);
        var bytes = new byte[Length];
        xo.NextBytes(bytes);

        xo.Reset(43);
        var bytes2 = new byte[Length2];
        var ulongs = MemoryMarshal.Cast<byte, ulong>(bytes2.AsSpan());
        for (var i = 0; i < Length2 / sizeof(ulong); i++)
        {
            ulongs[i] = xo.NextUInt64();
        }

        bytes.AsSpan().SequenceEqual(bytes2.AsSpan(0, Length)).IsTrue();
    }

    [Fact]
    public void NextStateMatchesReferenceImplementation()
    {
        // Outputs of the reference xoroshiro128starstar.c from the raw state { 1, 2 },
        // as listed in the "reference" test of rand_xoshiro (https://github.com/rust-random/rngs, rand_xoshiro/src/xoroshiro128starstar.rs).
        ulong[] expected =
        [
            5760, 97769243520, 9706862127477703552, 9223447511460779954, 8358291023205304566,
            15695619998649302768, 8517900938696309774, 16586480348202605369, 6959129367028440372, 16822147227405758281,
        ];

        ulong s0 = 1;
        ulong s1 = 2;
        var reference = new Reference(1, 2);
        foreach (var x in expected)
        {
            reference.Next().Is(x);
            Xoroshiro128StarStar.NextState(ref s0, ref s1).Is(x);
        }

        // Longer runs from other raw states against the inline port of the reference code.
        foreach (var (a, b) in new[] { (0x0123456789ABCDEFUL, 0xFEDCBA9876543210UL), (0UL, 1UL), (ulong.MaxValue, 0UL) })
        {
            reference = new Reference(a, b);
            s0 = a;
            s1 = b;
            for (var i = 0; i < 1000; i++)
            {
                Xoroshiro128StarStar.NextState(ref s0, ref s1).Is(reference.Next());
            }

            s0.Is(reference.S0);
            s1.Is(reference.S1);
        }
    }

    [Fact]
    public void SeedIsExpandedWithSplitMix64()
    {
        foreach (var seed in new ulong[] { 0, 43, ulong.MaxValue, })
        {
            // splitmix64.c (https://prng.di.unimi.it/splitmix64.c), as recommended by xoroshiro128starstar.c for seeding.
            var x = seed;
            var reference = new Reference(SplitMix64(ref x), SplitMix64(ref x));

            Xoroshiro128StarStar.InitializeState(seed, out var a0, out var a1);
            a0.Is(reference.S0);
            a1.Is(reference.S1);

            var xo = new Xoroshiro128StarStar(seed);
            for (var i = 0; i < 100; i++)
            {
                xo.NextUInt64().Is(reference.Next());
            }

            xo.Reset(seed);
            xo.NextUInt64().Is(Xoroshiro128StarStar.NextState(ref a0, ref a1));
        }

        static ulong SplitMix64(ref ulong x)
        {
            var z = x += 0x9e3779b97f4a7c15;
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
            z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
            return z ^ (z >> 31);
        }
    }

    [Fact]
    public void NextBytesTailsConsumeWholeWords()
    {
        for (var length = 0; length <= 32; length++)
        {
            var random = new Xoroshiro128StarStar(7);
            var reference = new Xoroshiro128StarStar(7);
            var words = new ulong[(length + 7) / 8];
            for (var i = 0; i < words.Length; i++)
            {
                words[i] = reference.NextUInt64();
            }

            var output = new byte[length + 2];
            output.AsSpan().Fill(0xA5);
            random.NextBytes(output.AsSpan(1, length));
            output.AsSpan(1, length).SequenceEqual(MemoryMarshal.AsBytes(words.AsSpan()).Slice(0, length)).IsTrue();
            output[0].Is((byte)0xA5);
            output[^1].Is((byte)0xA5);
            random.NextUInt64().Is(reference.NextUInt64());
        }
    }

    [Fact]
    public void RandomSeedResetsState()
    {
        // Collisions of independent 64-bit outputs have probability 2^-64.
        var a = new Xoroshiro128StarStar();
        var b = new Xoroshiro128StarStar();
        a.NextUInt64().IsNot(b.NextUInt64());

        a.Reset(43);
        var seeded = a.NextUInt64();
        a.Reset();
        a.NextUInt64().IsNot(seeded);
        (a.NextUInt64() | a.NextUInt64()).IsNot(0UL);
        a.Reset(43);
        a.NextUInt64().Is(seeded);
    }

    /// <summary>
    /// Inline port of next() in https://prng.di.unimi.it/xoroshiro128starstar.c.
    /// </summary>
    private sealed class Reference(ulong s0, ulong s1)
    {
        public ulong S0 { get; private set; } = s0;

        public ulong S1 { get; private set; } = s1;

        public ulong Next()
        {
            var t0 = this.S0;
            var t1 = this.S1;
            var result = Rotl(t0 * 5, 7) * 9;

            t1 ^= t0;
            this.S0 = Rotl(t0, 24) ^ t1 ^ (t1 << 16); // a, b
            this.S1 = Rotl(t1, 37); // c

            return result;
        }

        private static ulong Rotl(ulong x, int k) => (x << k) | (x >> (64 - k));
    }
}
