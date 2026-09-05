// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Arc.Crypto;
using Arc.Crypto.EC;
using Xunit;

namespace Test;

public class BoundaryRegressionTest
{
    [Fact]
    public void Base32LengthsDoNotOverflow()
    {
        foreach (var length in new[] { 0, 1, 5, 268_435_456, 1_342_177_279, })
        {
            Assert.Equal((int)((((long)length * 8) + 4) / 5), Base32Sort.GetEncodedLength(length));
        }

        Assert.Equal(1_342_177_279, Base32Sort.GetDecodedLength(int.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(() => Base32Sort.GetEncodedLength(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Base32Sort.GetEncodedLength(1_342_177_280));
        Assert.Throws<ArgumentOutOfRangeException>(() => Base32Sort.GetEncodedLength(int.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(() => Base32Sort.GetDecodedLength(-1));
    }

    [Fact]
    public void RandomRangesRejectInvalidBounds()
    {
        var random = new Xoshiro256StarStar(42);
        Assert.Throws<ArgumentOutOfRangeException>(() => random.NextInt32(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => random.NextInt64(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => random.NextInt32(1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => random.NextInt64(1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => random.NextInt32(int.MaxValue, int.MinValue));
        Assert.Throws<ArgumentOutOfRangeException>(() => random.NextInt64(long.MaxValue, long.MinValue));
        Assert.Throws<ArgumentNullException>(() => new RandomVault(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RandomVault(static bytes => bytes.Clear(), -1));
    }

    [Fact]
    public void RandomRangesAndFloatingPointEndpoints()
    {
        var random = new ConstantRandom(0);
        Assert.Equal(0, RandomUInt64.Log2Ceiling(0));
        Assert.Equal(0, RandomUInt64.Log2Ceiling(1));
        Assert.Equal(64, RandomUInt64.Log2Ceiling(ulong.MaxValue));
        for (var bit = 1; bit < 64; bit++)
        {
            Assert.Equal(bit, RandomUInt64.Log2Ceiling(1UL << bit));
            Assert.Equal(bit + 1, RandomUInt64.Log2Ceiling((1UL << bit) + 1));
        }

        Assert.Equal(0, random.NextInt32(0));
        Assert.Equal(0, random.NextInt64(1));
        Assert.Equal(7, random.NextInt32(7, 7));
        Assert.Equal(-7, random.NextInt64(-7, -7));
        Assert.Equal(int.MinValue, random.NextInt32(int.MinValue, int.MaxValue));
        Assert.Equal(long.MinValue, random.NextInt64(long.MinValue, long.MaxValue));
        Assert.Equal(0, random.NextDouble());
        Assert.Equal(0, random.NextDouble2());
        Assert.True(random.NextDouble3() > 0);
        random.Value = ulong.MaxValue;
        Assert.Equal(ulong.MaxValue, random.NextUInt64());
        Assert.Equal(long.MaxValue, random.NextInt63());
        Assert.Equal(uint.MaxValue, random.NextUInt32());
        Assert.Equal(-1, random.NextInt32());
        Assert.Equal(int.MaxValue, random.NextInt31());
        Assert.Equal(-1, random.NextInt64());
        Assert.True(random.NextDouble() < 1);
        Assert.Equal(1, random.NextDouble2());
        Assert.True(random.NextDouble3() < 1);
        Assert.True(random.NextSingle() < 1);

        var generator = new Xoshiro256StarStar(42);
        for (var i = 0; i < 10_000; i++)
        {
            Assert.InRange(generator.NextInt32(-5, 7), -5, 6);
            Assert.InRange(generator.NextInt64(long.MinValue, long.MaxValue), long.MinValue, long.MaxValue - 1);
            Assert.InRange(generator.NextInt64(13), 0, 12);
        }
    }

    [Fact]
    public void Sha2RejectsShortDestinationsBeforeWriting()
    {
        var buffer = Enumerable.Repeat((byte)0xA5, 80).ToArray();
        Assert.Throws<ArgumentException>(() => Sha2Helper.Get256_Span("abc"u8, buffer.AsSpan(0, 31)));
        Assert.Throws<ArgumentException>(() => Sha2Helper.Get384_Span("abc"u8, buffer.AsSpan(0, 47)));
        Assert.Throws<ArgumentException>(() => Sha2Helper.Get512_Span("abc"u8, buffer.AsSpan(0, 63)));

        // The backing array is large enough even on the old, unchecked native path.
        Assert.Throws<ArgumentException>(() => Sha2Helper.Get512_Libsodium("abc"u8, buffer.AsSpan(0, 63)));
        Assert.All(buffer, value => Assert.Equal(0xA5, value));
    }

    [Theory]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(512)]
    public void Sha3InitializesCallerState(int bits)
    {
        Span<ulong> state = stackalloc ulong[25];
        state.Fill(ulong.MaxValue);
        var sponge = new KeccakSpongeStruct(bits, state);
        sponge.Absorb("abc"u8);
        Span<byte> output = stackalloc byte[64];
        sponge.SqueezeTo(output);
        var expected = bits switch
        {
            256 => Sha3Helper.Get256_ByteArray("abc"u8),
            384 => Sha3Helper.Get384_ByteArray("abc"u8),
            _ => Sha3Helper.Get512_ByteArray("abc"u8),
        };
        Assert.Equal(expected, output[..(bits / 8)].ToArray());
    }

    [Fact]
    public void CurveRejectsNonCanonicalCoordinates()
    {
        foreach (var curve in new ECCurveBase[] { P256K1Curve.Instance, P256R1Curve.Instance, })
        {
            var q = new BigInteger(curve.ByteQ, isUnsigned: true, isBigEndian: true);
            for (var offset = 0; offset < 32; offset++)
            {
                var x = (q + offset).ToByteArray(isUnsigned: true, isBigEndian: true);
                Assert.Null(curve.TryDecompressY(x, 0));
                Assert.Null(curve.TryDecompressY(x, 1));
            }
        }
    }

    [Fact]
    public void SeedValidationMatchesBigIntegerReference()
    {
        var random = new Random(42);
        var seed = new byte[32];
        foreach (var curve in new ECCurveBase[] { P256K1Curve.Instance, P256R1Curve.Instance, })
        {
            var order = new BigInteger(curve.ByteOrder, isUnsigned: true, isBigEndian: true);
            for (var i = 0; i < 2_000; i++)
            {
                random.NextBytes(seed);
                if (i < 256)
                {
                    seed.AsSpan().Fill((byte)i);
                }

                var value = new BigInteger(seed, isUnsigned: true, isBigEndian: true);
                var weight = (int)BigInteger.PopCount((value * 3) ^ value);
                Assert.Equal(value > 0 && value < order && weight >= 64, curve.IsValidSeed(seed));
            }
        }
    }

    private sealed class ConstantRandom(ulong value) : RandomUInt64
    {
        public ulong Value { get; set; } = value;

        public override ulong NextUInt64() => this.Value;
    }
}
