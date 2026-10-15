// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Arc.Crypto.EC;
using Xunit;

namespace Test;

/// <summary>
/// Field arithmetic of <see cref="Secp256k1Curve"/> and <see cref="Secp256r1Curve"/> checked against
/// <see cref="BigInteger"/> arithmetic modulo p, with inputs chosen to reach carry chains and the rare
/// correction branches of the reductions.
/// </summary>
public class ECElementTest
{
    private static readonly BigInteger Two256 = BigInteger.One << 256;
    private static readonly BigInteger Max256 = Two256 - 1;

    public static TheoryData<string> CurveNames => new() { "secp256k1", "secp256r1" };

    [Theory]
    [MemberData(nameof(CurveNames))]
    public void Operations_MatchBigInteger_OnBoundaryValues(string curveName)
    {
        var curve = GetCurve(curveName);
        var p = ToBig(curve.UIntQ);
        var values = BoundaryValues(p);
        var w = new uint[8];
        var z = new uint[8];

        foreach (var a in values)
        {
            var x = FromBig(a);
            (curve.ElementIsZero(x) != 0).Is(a.IsZero);

            curve.ElementSquare(x, z);
            ToBig(z).Is((a * a) % p);
            x.CopyTo(w, 0);
            curve.ElementSquare(w, w);
            w.Is(z);

            curve.ElementNegate(x, z);
            ToBig(z).Is((p - a) % p);
            x.CopyTo(w, 0);
            curve.ElementNegate(w, w);
            w.Is(z);

            foreach (var b in values)
            {
                var y = FromBig(b);
                curve.ElementAdd(x, y, z);
                ToBig(z).Is((a + b) % p);
                curve.ElementMultiply(x, y, z);
                ToBig(z).Is((a * b) % p);
            }

            // In place: the output span is one of the operands.
            x.CopyTo(w, 0);
            curve.ElementAdd(w, x, w);
            ToBig(w).Is((a + a) % p);
            x.CopyTo(w, 0);
            curve.ElementMultiply(x, w, w);
            ToBig(w).Is((a * a) % p);
        }
    }

    [Theory]
    [MemberData(nameof(CurveNames))]
    public void Operations_MatchBigInteger_OnRandomValues(string curveName)
    {
        var curve = GetCurve(curveName);
        var p = ToBig(curve.UIntQ);
        var rng = new Random(curveName == "secp256k1" ? 1017 : 2017); // A distinct, fixed seed per curve.
        var z = new uint[8];

        for (var i = 0; i < 1_000; i++)
        {
            var a = RandomFieldElement(rng, p, saturate: (i & 1) == 0);
            var b = RandomFieldElement(rng, p, saturate: (i & 2) == 0);
            var x = FromBig(a);
            var y = FromBig(b);

            curve.ElementAdd(x, y, z);
            ToBig(z).Is((a + b) % p);
            curve.ElementMultiply(x, y, z);
            ToBig(z).Is((a * b) % p);
            curve.ElementSquare(x, z);
            ToBig(z).Is((a * a) % p);
            curve.ElementNegate(y, z);
            ToBig(z).Is((p - b) % p);
        }
    }

    [Theory]
    [MemberData(nameof(CurveNames))]
    public void ElementAdd_CarryAndReductionBoundaries(string curveName)
    {
        var curve = GetCurve(curveName);
        var p = ToBig(curve.UIntQ);
        var z = new uint[8];

        // x = p - 1 and y = t - x < p, so the true sum is t: exactly p, just above p, and sums that carry out of 2^256.
        var targets = new[]
        {
            p, p + 1, p + (BigInteger.One << 192), Two256 - 1, Two256, Two256 + 1,
            Two256 + ((BigInteger)0xFFFFFFFF << 32), (2 * p) - 2,
        };
        foreach (var t in targets)
        {
            curve.ElementAdd(FromBig(p - 1), FromBig(t - (p - 1)), z);
            ToBig(z).Is(t % p);
        }

        // Sums below p whose top word is 0xFFFFFFFF: the comparison with p must look at lower words.
        foreach (var t in new[] { (BigInteger)0xFFFFFFFF << 224, p - 1, p - Two256 + Max256 - (BigInteger.One << 64) })
        {
            if (t < p)
            {
                curve.ElementAdd(FromBig(t - 1), FromBig(BigInteger.One), z);
                ToBig(z).Is(t);
            }
        }
    }

    [Theory]
    [MemberData(nameof(CurveNames))]
    public void ElementSqrt_MatchesEulerCriterion(string curveName)
    {
        var curve = GetCurve(curveName);
        var p = ToBig(curve.UIntQ);
        var rng = new Random(321);
        var values = Enumerable.Range(0, 64).Select(i => (BigInteger)i).ToList();
        values.AddRange([p - 1, p - 2, p - 4, 1 + (BigInteger.One << 64), 1 + (BigInteger.One << 224), (BigInteger.One << 32) + 1]);
        for (var i = 0; i < 60; i++)
        {
            values.Add(RandomFieldElement(rng, p, saturate: false));
            var r = RandomFieldElement(rng, p, saturate: true);
            values.Add((r * r) % p); // a square by construction
        }

        var z = new uint[8];
        var squares = 0;
        var nonSquares = 0;
        foreach (var v in values)
        {
            var expected = v.IsZero || BigInteger.ModPow(v, (p - 1) / 2, p).IsOne;
            var x = FromBig(v);
            z.AsSpan().Fill(0xAAAAAAAA);
            curve.ElementSqrt(x, z).Is(expected);
            if (expected)
            {
                squares++;
                var root = ToBig(z);
                (root < p).IsTrue();
                ((root * root) % p).Is(v);
            }
            else
            {
                nonSquares++;
                z.All(word => word == 0xAAAAAAAA).IsTrue(); // not written on failure
            }

            // In place.
            var w = FromBig(v);
            curve.ElementSqrt(w, w).Is(expected);
            if (expected)
            {
                w.Is(z);
            }
            else
            {
                w.Is(x);
            }
        }

        (squares > 40 && nonSquares > 40).IsTrue();

        // p = 3 mod 4 on both curves, so -1 is not a square.
        curve.ElementSqrt(FromBig(p - 1), z).IsFalse();

        // 0 and 1 are their own square roots.
        z.AsSpan().Fill(0xAAAAAAAA);
        curve.ElementSqrt(new uint[8], z).IsTrue();
        z.Is(new uint[8]);
        curve.ElementSqrt(FromBig(BigInteger.One), z).IsTrue();
        z.Is(FromBig(BigInteger.One));
    }

    [Theory]
    [MemberData(nameof(CurveNames))]
    public void ElementNegate_ZeroAndOne(string curveName)
    {
        var curve = GetCurve(curveName);
        var p = ToBig(curve.UIntQ);
        var z = new uint[8];

        z.AsSpan().Fill(0xAAAAAAAA);
        curve.ElementNegate(new uint[8], z);
        z.Is(new uint[8]); // -0 is 0, not p

        curve.ElementNegate(FromBig(BigInteger.One), z);
        ToBig(z).Is(p - 1);
        curve.ElementNegate(FromBig(p - 1), z);
        ToBig(z).Is(BigInteger.One);

        var x = new uint[8];
        curve.ElementNegate(x, x);
        x.Is(new uint[8]);
    }

    /// <summary>
    /// secp256r1 reduction on crafted inputs. Results in <c>[p, 2^256)</c> and the inner carries of the
    /// word-based correction occur with probability around 2^-32 for random operands.
    /// </summary>
    [Fact]
    public void P256R1_ReduceBoundaries()
    {
        var curve = Secp256r1Curve.Instance;
        var p = ToBig(curve.UIntQ);
        var rng = new Random(256);
        var candidates = new List<BigInteger> { Max256, Max256 - 1 };
        for (var k = 0; k < 64; k++)
        {
            candidates.Add(p + k);
            candidates.Add(((BigInteger)0xFFFFFFFF << 96) + k);
            candidates.Add(((BigInteger)0xFFFFFFFA << 96) + k);
        }

        for (var w = 0; w < 8; w++)
        {
            var word = (BigInteger)0xFFFFFFFF << (32 * w);
            candidates.Add(Max256 - word);
            candidates.Add(word);
            if (p + word < Two256)
            {
                candidates.Add(p + word);
            }
        }

        for (var i = 0; i < 2_000; i++)
        {
            candidates.Add(p + RandomBelow(rng, Two256 - p));
        }

        var xx = new uint[16];
        var z = new uint[8];
        var two = FromBig(2);
        foreach (var n in candidates)
        {
            // Directly, as a 512-bit value with a zero high half.
            FromBig(n).CopyTo(xx, 0);
            Array.Clear(xx, 8, 8);
            Secp256r1Curve.Reduce(xx, z);
            ToBig(z).Is(n % p);

            // Through the public API: both operands are below p.
            if (n.IsEven)
            {
                curve.ElementMultiply(two, FromBig(n / 2), z);
                ToBig(z).Is(n % p);
            }
        }

        // 512-bit inputs with a non-zero high half.
        var highs = new[] { BigInteger.Zero, BigInteger.One, p - 1, p, Max256, (BigInteger)0xFFFFFFFF << 224 };
        foreach (var hi in highs)
        {
            foreach (var lo in new[] { BigInteger.Zero, BigInteger.One, p - 1, p, Max256, RandomBelow(rng, Two256) })
            {
                var value = (hi << 256) | lo;
                FromBig(value, 16).CopyTo(xx, 0);
                Secp256r1Curve.Reduce(xx, z);
                ToBig(z).Is(value % p);
            }
        }

        for (var i = 0; i < 2_000; i++)
        {
            var value = RandomBelow(rng, Two256 * Two256);
            FromBig(value, 16).CopyTo(xx, 0);
            Secp256r1Curve.Reduce(xx, z);
            ToBig(z).Is(value % p);
        }
    }

    /// <summary>
    /// Inputs whose squares fall in <c>[p, 2^256)</c> before the final correction (secp256r1: just above sqrt(p);
    /// secp256k1: p - k, whose square folds to k^2 + p), so the correction inside the fused loops runs.
    /// </summary>
    [Fact]
    public void ElementSquareN_CorrectionBoundaries()
    {
        var a = new uint[8];
        var b = new uint[8];
        var c = new uint[8];

        var pR1 = ToBig(Secp256r1Curve.Instance.UIntQ);
        var s = CeilingSqrt(pR1);
        for (var i = 0; i < 64; i++)
        {
            Verify(Secp256r1Curve.Instance, pR1, s + i);
        }

        var pK1 = ToBig(Secp256k1Curve.Instance.UIntQ);
        for (var k = 1; k <= 64; k++)
        {
            Verify(Secp256k1Curve.Instance, pK1, pK1 - k);
        }

        void Verify(ECCurveBase curve, BigInteger p, BigInteger value)
        {
            var x = FromBig(value);
            for (var n = 1; n <= 3; n++)
            {
                SquareN(curve, x, n, a);
                SquareNSoft(curve, x, n, b);
                x.CopyTo(c, 0);
                for (var j = 0; j < n; j++)
                {
                    curve.ElementSquare(c, c);
                }

                var expected = BigInteger.ModPow(value, BigInteger.One << n, p);
                ToBig(a).Is(expected);
                b.Is(a);
                c.Is(a);
            }
        }
    }

    [Theory]
    [MemberData(nameof(CurveNames))]
    public void ElementSquareNSoft_MatchesFused(string curveName)
    {
        var curve = GetCurve(curveName);
        var p = ToBig(curve.UIntQ);
        var rng = new Random(1010);
        var values = BoundaryValues(p);
        for (var i = 0; i < 300; i++)
        {
            values.Add(RandomFieldElement(rng, p, saturate: (i & 1) == 0));
        }

        var a = new uint[8];
        var b = new uint[8];
        foreach (var v in values)
        {
            var x = FromBig(v);
            var n = 1 + rng.Next(10);
            SquareN(curve, x, n, a);
            SquareNSoft(curve, x, n, b);
            ToBig(a).Is(BigInteger.ModPow(v, BigInteger.One << n, p));
            b.Is(a);

            // In place.
            SquareNSoft(curve, x, n, x);
            x.Is(a);
        }
    }

    private static ECCurveBase GetCurve(string name) => name == "secp256k1" ? Secp256k1Curve.Instance : Secp256r1Curve.Instance;

    private static void SquareN(ECCurveBase curve, ReadOnlySpan<uint> x, int n, Span<uint> z)
    {
        if (curve is Secp256k1Curve)
        {
            Secp256k1Curve.ElementSquareN(x, n, z);
        }
        else
        {
            Secp256r1Curve.ElementSquareN(x, n, z);
        }
    }

    private static void SquareNSoft(ECCurveBase curve, ReadOnlySpan<uint> x, int n, Span<uint> z)
    {
        if (curve is Secp256k1Curve)
        {
            Secp256k1Curve.ElementSquareNSoft(x, n, z);
        }
        else
        {
            Secp256r1Curve.ElementSquareNSoft(x, n, z);
        }
    }

    /// <summary>
    /// Canonical values (below p) with long runs of 0 and 0xFFFFFFFF words, powers of two and values near p.
    /// </summary>
    private static List<BigInteger> BoundaryValues(BigInteger p)
    {
        var list = new List<BigInteger>
        {
            0, 1, 2, 3, p - 1, p - 2, p - 3, (p - 1) / 2, (p + 1) / 2, CeilingSqrt(p), CeilingSqrt(p) - 1,
        };

        for (var bits = 32; bits < 256; bits += 32)
        {
            list.Add((BigInteger.One << bits) - 1);
            list.Add(BigInteger.One << bits);
            list.Add(p - (BigInteger.One << bits));
        }

        list.Add(BigInteger.One << 255);
        list.Add((BigInteger.One << 255) - 1);
        for (var w = 0; w < 8; w++)
        {
            list.Add((BigInteger)0xFFFFFFFF << (32 * w));
            list.Add(Max256 - ((BigInteger)0xFFFFFFFF << (32 * w)));
        }

        return list.Where(v => v.Sign >= 0 && v < p).Distinct().ToList();
    }

    private static BigInteger RandomFieldElement(Random rng, BigInteger p, bool saturate)
    {
        while (true)
        {
            var words = new uint[8];
            for (var i = 0; i < 8; i++)
            {
                words[i] = (uint)rng.NextInt64(0, 1L << 32);
                if (saturate && rng.Next(3) == 0)
                {
                    words[i] = rng.Next(2) == 0 ? 0xFFFFFFFF : 0;
                }
            }

            var v = ToBig(words);
            if (v < p)
            {
                return v;
            }
        }
    }

    private static BigInteger RandomBelow(Random rng, BigInteger bound)
    {
        var bytes = new byte[(int)(bound.GetBitLength() / 8) + 9];
        rng.NextBytes(bytes);
        return new BigInteger(bytes, isUnsigned: true) % bound;
    }

    private static BigInteger CeilingSqrt(BigInteger n)
    {
        var x = BigInteger.One << (int)((n.GetBitLength() + 1) / 2);
        while (true)
        {
            var y = (x + (n / x)) >> 1;
            if (y >= x)
            {
                break;
            }

            x = y;
        }

        return x * x < n ? x + 1 : x;
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

    private static uint[] FromBig(BigInteger v, int words = 8)
    {
        var x = new uint[words];
        for (var i = 0; i < words; i++)
        {
            x[i] = (uint)(v & 0xFFFFFFFF);
            v >>= 32;
        }

        return x;
    }
}
