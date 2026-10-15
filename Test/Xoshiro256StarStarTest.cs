// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Xoshiro256StarStarTest
{
    private const int Length = 1023;
    private const int Length2 = 1024;

    [Fact]
    public void Test1()
    {
        // SplitMix64
        var seed = 1234567ul;
        Xoshiro256StarStar.SplitMix64(ref seed).Is(6457827717110365317ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(3203168211198807973ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(9817491932198370423ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(4593380528125082431ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(16408922859458223821ul);

        var xo = new Xoshiro256StarStar(42);
        DoubleToString(xo.NextDouble()).Is("0.0838629710598822");
        DoubleToString(xo.NextDouble()).Is("0.3789802506626686");
        DoubleToString(xo.NextDouble()).Is("0.6800434110281394");
        DoubleToString(xo.NextDouble()).Is("0.9246929453253876");
        DoubleToString(xo.NextDouble()).Is("0.9918039142821028");

        string DoubleToString(double d) => d.ToString("F16");

        xo.NextUInt64().Is(14199186830065750584ul);
        xo.NextUInt64().Is(13267978908934200754ul);
        xo.NextUInt64().Is(15679888225317814407ul);
        xo.NextUInt64().Is(14044878350692344958ul);
        xo.NextUInt64().Is(10760895422300929085ul);

        xo = new Xoshiro256StarStar(43);
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
        // Outputs of the reference xoshiro256starstar.c from the raw state { 1, 2, 3, 4 },
        // as listed in the "reference" test of rand_xoshiro (https://github.com/rust-random/rngs, rand_xoshiro/src/xoshiro256starstar.rs).
        ulong[] expected =
        [
            11520, 0, 1509978240, 1215971899390074240, 1216172134540287360,
            607988272756665600, 16172922978634559625, 8476171486693032832, 10595114339597558777, 2904607092377533576,
        ];

        ulong s0 = 1;
        ulong s1 = 2;
        ulong s2 = 3;
        ulong s3 = 4;
        var reference = new Reference(1, 2, 3, 4);
        foreach (var x in expected)
        {
            reference.Next().Is(x);
            Xoshiro256StarStar.NextState(ref s0, ref s1, ref s2, ref s3).Is(x);
        }

        // Longer runs from other raw states against the inline port of the reference code.
        foreach (var state in new ulong[][] { [0x0123456789ABCDEFUL, 0xFEDCBA9876543210UL, 0x0F1E2D3C4B5A6978UL, 0x8796A5B4C3D2E1F0UL], [0, 0, 0, 1], [ulong.MaxValue, 0, ulong.MaxValue, 0], })
        {
            reference = new Reference(state[0], state[1], state[2], state[3]);
            s0 = state[0];
            s1 = state[1];
            s2 = state[2];
            s3 = state[3];
            for (var i = 0; i < 1000; i++)
            {
                Xoshiro256StarStar.NextState(ref s0, ref s1, ref s2, ref s3).Is(reference.Next());
            }

            s0.Is(reference.S0);
            s1.Is(reference.S1);
            s2.Is(reference.S2);
            s3.Is(reference.S3);
        }
    }

    [Fact]
    public void SeedIsExpandedWithSplitMix64()
    {
        foreach (var seed in new ulong[] { 0, 42, ulong.MaxValue, })
        {
            // splitmix64.c (https://prng.di.unimi.it/splitmix64.c), as recommended by xoshiro256starstar.c for seeding.
            var x = seed;
            var reference = new Reference(SplitMix64(ref x), SplitMix64(ref x), SplitMix64(ref x), SplitMix64(ref x));

            Xoshiro256StarStar.InitializeState(seed, out var a0, out var a1, out var a2, out var a3);
            a0.Is(reference.S0);
            a1.Is(reference.S1);
            a2.Is(reference.S2);
            a3.Is(reference.S3);

            var xo = new Xoshiro256StarStar(seed);
            for (var i = 0; i < 100; i++)
            {
                xo.NextUInt64().Is(reference.Next());
            }

            xo.Reset(seed);
            xo.NextUInt64().Is(Xoshiro256StarStar.NextState(ref a0, ref a1, ref a2, ref a3));
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
            var random = new Xoshiro256StarStar(7);
            var reference = new Xoshiro256StarStar(7);
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
        var a = new Xoshiro256StarStar();
        var b = new Xoshiro256StarStar();
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
    /// Inline port of next() in https://prng.di.unimi.it/xoshiro256starstar.c.
    /// </summary>
    private sealed class Reference(ulong s0, ulong s1, ulong s2, ulong s3)
    {
        public ulong S0 { get; private set; } = s0;

        public ulong S1 { get; private set; } = s1;

        public ulong S2 { get; private set; } = s2;

        public ulong S3 { get; private set; } = s3;

        public ulong Next()
        {
            var result = Rotl(this.S1 * 5, 7) * 9;

            var t = this.S1 << 17;

            this.S2 ^= this.S0;
            this.S3 ^= this.S1;
            this.S1 ^= this.S2;
            this.S0 ^= this.S3;

            this.S2 ^= t;

            this.S3 = Rotl(this.S3, 45);

            return result;
        }

        private static ulong Rotl(ulong x, int k) => (x << k) | (x >> (64 - k));
    }
}
