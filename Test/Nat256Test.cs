// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Numerics;
using Arc.Crypto.EC;
using Xunit;

namespace Test;

/// <summary>
/// The multi-word helpers behind the EC field arithmetic (<see cref="Nat256"/> and <see cref="Nat"/>),
/// checked against <see cref="BigInteger"/> and against the portable 32-bit implementations.
/// </summary>
public class Nat256Test
{
    private static readonly BigInteger Two256 = BigInteger.One << 256;
    private static readonly BigInteger Max256 = Two256 - 1;

    [Fact]
    public void AddSub_MatchBigInteger()
    {
        var values = Values(new Random(11), 60);
        var z = new uint[8];
        foreach (var a in values)
        {
            var x = FromBig(a);
            foreach (var b in values)
            {
                var y = FromBig(b);

                var carry = Nat256.Add(x, y, z);
                ((carry * Two256) + ToBig(z)).Is(a + b);

                var borrow = Nat256.Sub(x, y, z);
                (borrow == 0 || borrow == -1).IsTrue();
                ((borrow * Two256) + ToBig(z)).Is(a - b);
            }

            // In place.
            var w = FromBig(a);
            Nat256.Add(w, w, w);
            ToBig(w).Is((a + a) % Two256);
            w = FromBig(a);
            Nat256.Sub(w, w, w);
            ToBig(w).IsZero.IsTrue();
        }
    }

    /// <summary>
    /// The 64-bit limb fast paths must agree with the portable 32-bit paths and with <see cref="BigInteger"/>
    /// on every pair of boundary values (all-ones words, single words, powers of two).
    /// </summary>
    [Fact]
    public void MulSquare_MatchSoftAndBigInteger()
    {
        var values = Values(new Random(12), 40);
        var zzA = new uint[16];
        var zzB = new uint[16];
        foreach (var a in values)
        {
            var x = FromBig(a);
            Nat256.Square(x, zzA);
            Nat256.SquareSoft(x, zzB);
            ToBig(zzA).Is(a * a);
            zzB.Is(zzA);

            foreach (var b in values)
            {
                var y = FromBig(b);
                Nat256.Mul(x, y, zzA);
                Nat256.MulSoft(x, y, zzB);
                ToBig(zzA).Is(a * b);
                zzB.Is(zzA);
            }
        }
    }

    [Fact]
    public void Mul33Helpers_MatchBigInteger()
    {
        var rng = new Random(13);
        var values = Values(rng, 15);
        var z = new uint[16];
        var source = new uint[24];
        foreach (var a in values)
        {
            foreach (var b in values)
            {
                foreach (var w in new uint[] { 0, 1, 0x3D1, 0x7FFFFFFF })
                {
                    // (2^32 + w) * x + y at non-zero offsets.
                    Array.Clear(source);
                    FromBig(a).CopyTo(source, 8);
                    FromBig(b).CopyTo(source, 16);
                    var high = Nat256.Mul33Add(w, source, 8, source, 16, z, 4);
                    var expected = (((BigInteger)w + (BigInteger.One << 32)) * a) + b;
                    (((BigInteger)high << 256) + ToBig(z.AsSpan(4, 8))).Is(expected);

                    // z[0..7] += (2^32 + w) * y64.
                    var y64 = (ulong)(b & ulong.MaxValue);
                    FromBig(a).CopyTo(z, 0);
                    var carry = Nat256.Mul33DWordAdd(w, y64, z, 0);
                    (((BigInteger)carry << 256) + ToBig(z.AsSpan(0, 8))).Is(a + (((BigInteger)w + (BigInteger.One << 32)) * y64));
                }
            }
        }
    }

    [Fact]
    public void NatCarryHelpers_MatchBigInteger()
    {
        foreach (var a in Values(new Random(14), 100))
        {
            foreach (var x in new uint[] { 0, 1, 0x3D1, 0xFFFFFFFF })
            {
                var z = FromBig(a);
                var carry = Nat.Add33To(8, x, z);
                (((BigInteger)carry << 256) + ToBig(z)).Is(a + x + (BigInteger.One << 32));
            }

            for (var pos = 0; pos <= 8; pos++)
            {
                var z = FromBig(a);
                var carry = Nat.IncAt(8, z, pos);
                (((BigInteger)carry << 256) + ToBig(z)).Is(a + (BigInteger.One << (32 * pos)));
            }
        }

        // The offset overload: increment word 4 of the window starting at z[0].
        var window = new uint[] { 0, 0, 0, 0, 0xFFFFFFFF, 0, 0, 0 };
        Nat.IncAt(8, window, 0, 4).Is(0u);
        window.Is(new uint[] { 0, 0, 0, 0, 0, 1, 0, 0 });

        window = [7, 7, 7, 7, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];
        Nat.IncAt(8, window, 0, 4).Is(1u);
        window.Is(new uint[] { 7, 7, 7, 7, 0, 0, 0, 0 });

        var shifted = new uint[] { 9, 9, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0 };
        Nat.IncAt(4, shifted, 2, 0).Is(0u);
        shifted.Is(new uint[] { 9, 9, 0, 0, 1, 0 });
    }

    [Fact]
    public void Predicates_MatchBigInteger()
    {
        var values = Values(new Random(15), 80);
        values.Add(1 + (BigInteger.One << 64));
        values.Add(1 + (BigInteger.One << 224));
        foreach (var a in values)
        {
            var x = FromBig(a);
            Nat256.IsZero(x).Is(a.IsZero);
            Nat256.IsOne(x).Is(a.IsOne);
            foreach (var b in values)
            {
                Nat256.Gte(x, FromBig(b)).Is(a >= b);
            }
        }
    }

    /// <summary>
    /// Values below 2^256: 0, 1, all-ones, single all-ones words, runs of all-ones words, powers of two, and random values.
    /// </summary>
    private static List<BigInteger> Values(Random rng, int randomCount)
    {
        var list = new List<BigInteger> { 0, 1, 2, Max256, Max256 - 1, BigInteger.One << 255 };
        for (var w = 0; w < 8; w++)
        {
            list.Add((BigInteger)0xFFFFFFFF << (32 * w));
            list.Add((BigInteger.One << (32 * (w + 1))) - 1);
            list.Add(Max256 - ((BigInteger)0xFFFFFFFF << (32 * w)));
        }

        for (var i = 0; i < randomCount; i++)
        {
            var words = new uint[8];
            for (var j = 0; j < 8; j++)
            {
                words[j] = (uint)rng.NextInt64(0, 1L << 32);
                if (rng.Next(3) == 0)
                {
                    words[j] = rng.Next(2) == 0 ? 0xFFFFFFFF : 0;
                }
            }

            list.Add(ToBig(words));
        }

        return list;
    }

    private static BigInteger ToBig(ReadOnlySpan<uint> x)
    {
        BigInteger v = 0;
        for (var i = x.Length - 1; i >= 0; i--)
        {
            v = (v << 32) | x[i];
        }

        return v;
    }

    private static uint[] FromBig(BigInteger v)
    {
        var x = new uint[8];
        for (var i = 0; i < 8; i++)
        {
            x[i] = (uint)(v & 0xFFFFFFFF);
            v >>= 32;
        }

        return x;
    }
}
