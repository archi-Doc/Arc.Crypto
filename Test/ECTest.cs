// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Arc.Crypto;
using Arc.Crypto.EC;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access

namespace Test;

public class ECTest
{
    [Fact]
    public void Test1()
    {
        var curve = ECCurve.CreateFromFriendlyName("secp256r1");
        for (var i = 0; i < 100; i++)
        {
            using (var ecdh = ECDiffieHellman.Create(curve))
            {
                var p = ecdh.ExportParameters(false);

                var yt = P256R1Curve.Instance.CompressY(p.Q.Y!);
                var y = P256R1Curve.Instance.TryDecompressY(p.Q.X!, yt);
                y!.SequenceEqual(p.Q.Y!).IsTrue();
            }
        }

        curve = ECCurve.CreateFromFriendlyName("secp256k1");
        for (var i = 0; i < 100; i++)
        {
            using (var ecdh = ECDiffieHellman.Create(curve))
            {
                var p = ecdh.ExportParameters(false);

                var yt = P256K1Curve.Instance.CompressY(p.Q.Y!);
                var y = P256K1Curve.Instance.TryDecompressY(p.Q.X!, yt);
                y!.SequenceEqual(p.Q.Y!).IsTrue();
            }
        }
    }

    [Fact]
    public void SeedTest()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(x => xo.NextBytes(x));

        P256K1Curve.Instance.IsValidSeed(new byte[1]).IsFalse();

        var seed = new byte[P256K1Curve.Instance.ByteLength];
        P256K1Curve.Instance.IsValidSeed(seed).IsFalse();

        var order = Hex.FromStringToByteArray(P256K1Curve.HexOrder);
        P256K1Curve.Instance.IsValidSeed(order).IsFalse();
        order[order.Length - 1]++;
        P256K1Curve.Instance.IsValidSeed(order).IsFalse();

        for (var i = 0; i < 1; i++)
        {
            rv.NextBytes(seed);

            P256K1Curve.Instance.IsValidSeed(seed);
        }

        P256R1Curve.Instance.IsValidSeed(new byte[1]).IsFalse();

        seed = new byte[P256R1Curve.Instance.ByteLength];
        P256R1Curve.Instance.IsValidSeed(seed).IsFalse();

        order = Hex.FromStringToByteArray(P256R1Curve.HexOrder);
        P256R1Curve.Instance.IsValidSeed(order).IsFalse();
        order[order.Length - 1]++;
        P256R1Curve.Instance.IsValidSeed(order).IsFalse();

        for (var i = 0; i < 1; i++)
        {
            rv.NextBytes(seed);

            P256R1Curve.Instance.IsValidSeed(seed);
        }
    }

    [Fact]
    public void DualTest()
    {
        var total = 1_000;
        var curves = new ECCurveBase[]
        {
            P256K1Curve.Instance,
            P256R1Curve.Instance,
        };

        var random = new Random(130);
        var seed = new byte[32];
        foreach (var curve in curves)
        {
            ECParameters key = default;
            key.Curve = ECCurve.CreateFromFriendlyName(curve.CurveName);

            for (var i = 0; i < total; i++)
            {
                random.NextBytes(seed);
                key.D = seed;

                if (curve.IsValidSeed(seed))
                {// Valid
                    ECParameters key1;
                    using (var ecdsa = ECDsa.Create(key))
                    {
                        key1 = ecdsa.ExportParameters(true);
                    }

                    ECParameters key2;
                    using (var ecdh = ECDiffieHellman.Create(key))
                    {
                        key2 = ecdh.ExportParameters(true);
                    }

                    key1.Q.X!.SequenceEqual(key2.Q.X!).IsTrue();
                    key1.Q.Y!.SequenceEqual(key2.Q.Y!).IsTrue();
                    key1.D!.SequenceEqual(key2.D!).IsTrue();
                }
            }
        }
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

    /// <summary>
    /// The 64-bit limb fast paths of <see cref="Nat256"/> must agree bit for bit with the portable
    /// 32-bit implementations and with <see cref="BigInteger"/>, including carry-saturating inputs.
    /// </summary>
    [Fact]
    public void Nat256_FastVsSoft()
    {
        var rng = new Random(20260901);
        var x = new uint[8];
        var y = new uint[8];
        var zzA = new uint[16];
        var zzB = new uint[16];

        for (var i = 0; i < 20_000; i++)
        {
            for (var j = 0; j < 8; j++)
            {
                x[j] = (uint)rng.Next() ^ ((uint)rng.Next() << 16);
                y[j] = (uint)rng.Next() ^ ((uint)rng.Next() << 16);
                if ((rng.Next() & 3) == 0)
                {
                    x[j] = 0xFFFFFFFF;
                }

                if ((rng.Next() & 3) == 0)
                {
                    y[j] = 0xFFFFFFFF;
                }
            }

            Nat256.Mul(x, y, zzA);
            Nat256.MulSoft(x, y, zzB);
            zzA.AsSpan().SequenceEqual(zzB).IsTrue();
            (ToBig(zzA) == ToBig(x) * ToBig(y)).IsTrue();

            Nat256.Square(x, zzA);
            Nat256.SquareSoft(x, zzB);
            zzA.AsSpan().SequenceEqual(zzB).IsTrue();
        }
    }

    /// <summary>
    /// The secp256k1 64-bit reduction must match the portable reduction on inputs crafted to hit
    /// its rare branches: the second-fold carry out of 2^256, and results in <c>[p, 2^256)</c>.
    /// Random inputs cannot reach these (probability ~2^-32), hence the construction.
    /// </summary>
    [Fact]
    public void P256K1_ReduceBoundaries()
    {
        var rng = new Random(4242);
        var q = ToBig(P256K1Curve.Instance.UIntQ);
        var max = (BigInteger.One << 256) - 1;
        var c = (BigInteger.One << 32) + 977;
        var xx = new uint[16];
        var zA = new uint[8];
        var zB = new uint[8];

        void Verify(BigInteger lo, BigInteger hi)
        {
            for (var i = 0; i < 8; i++)
            {
                xx[i] = (uint)(lo & 0xFFFFFFFF);
                lo >>= 32;
            }

            for (var i = 8; i < 16; i++)
            {
                xx[i] = (uint)(hi & 0xFFFFFFFF);
                hi >>= 32;
            }

            P256K1Curve.Reduce(xx, zA);
            P256K1Curve.ReduceSoft(xx, zB);
            zA.AsSpan().SequenceEqual(zB).IsTrue();
            (ToBig(zA) == ToBig(xx) % q).IsTrue();
        }

        BigInteger RandBelow(BigInteger bound)
        {
            var bytes = new byte[33];
            rng.NextBytes(bytes);
            bytes[32] = 0;
            return new BigInteger(bytes) % bound;
        }

        Verify(q, 0);
        Verify(q + 1, 0);
        Verify(max, 0);
        for (var i = 0; i < 3000; i++)
        {
            Verify(max - RandBelow(BigInteger.One << 60), max); // second-fold carry
            Verify(q + RandBelow(c * c), 0); // p <= result < 2^256
            Verify(RandBelow(max + 1), RandBelow(max + 1)); // plain random
        }
    }

    /// <summary>
    /// The fused register square-and-reduce loops must agree with repeated single squarings
    /// and with <see cref="BigInteger"/> for both curves.
    /// </summary>
    [Fact]
    public void ElementSquareN_MatchesRepeatedSquares()
    {
        var rng = new Random(90210);
        var curves = new ECCurveBase[] { P256K1Curve.Instance, P256R1Curve.Instance };
        var x = new uint[8];
        var a = new uint[8];
        var b = new uint[8];

        foreach (var curve in curves)
        {
            var q = ToBig(curve.UIntQ);
            for (var i = 0; i < 500; i++)
            {
                while (true)
                {
                    for (var j = 0; j < 8; j++)
                    {
                        x[j] = (uint)rng.Next() ^ ((uint)rng.Next() << 16);
                        if ((i & 3) == 0 && (rng.Next() & 1) == 0)
                        {
                            x[j] = 0xFFFFFFFF;
                        }
                    }

                    if (ToBig(x) < q)
                    {
                        break;
                    }
                }

                var n = 1 + rng.Next(10);
                if (curve is P256K1Curve)
                {
                    P256K1Curve.ElementSquareN(x, n, a);
                }
                else
                {
                    P256R1Curve.ElementSquareN(x, n, a);
                }

                x.CopyTo(b, 0);
                var expected = ToBig(x);
                for (var j = 0; j < n; j++)
                {
                    curve.ElementSquare(b, b);
                    expected = (expected * expected) % q;
                }

                a.AsSpan().SequenceEqual(b).IsTrue();
                (ToBig(a) == expected).IsTrue();
            }
        }
    }

    /// <summary>
    /// Unit tests for the out-of-line correction helpers of the fused reductions. These paths run
    /// with probability ~2^-32 per reduction, so they are exercised directly on boundary values.
    /// </summary>
    [Fact]
    public void CorrectionHelpers()
    {
        var rng = new Random(5150);
        var pR1 = BigInteger.Parse("0" + P256R1Curve.HexQ, NumberStyles.HexNumber);
        var pK1 = BigInteger.Parse("0" + P256K1Curve.HexQ, NumberStyles.HexNumber);
        var two256 = BigInteger.One << 256;

        var values = new List<BigInteger>
        {
            0, 1, pR1 - 1, pR1, pR1 + 1, pK1 - 1, pK1, pK1 + 1, two256 - 1, two256 - 2,
        };
        for (var w = 0; w < 8; w++)
        {
            values.Add(((BigInteger)0xFFFFFFFF) << (32 * w));
            values.Add(two256 - 1 - (((BigInteger)0xFFFFFFFF) << (32 * w)));
        }

        for (var i = 0; i < 10_000; i++)
        {
            var bytes = new byte[33];
            rng.NextBytes(bytes);
            bytes[32] = 0;
            values.Add(new BigInteger(bytes) % two256);
        }

        var m = (BigInteger.One << 64) - 1;
        foreach (var v in values)
        {
            var r0 = (ulong)(v & m);
            var r1 = (ulong)((v >> 64) & m);
            var r2 = (ulong)((v >> 128) & m);
            var r3 = (ulong)((v >> 192) & m);

            var (a0, a1, a2, a3) = (r0, r1, r2, r3);
            P256R1Curve.AddPInv(ref a0, ref a1, ref a2, ref a3);
            var joined = a0 | ((BigInteger)a1 << 64) | ((BigInteger)a2 << 128) | ((BigInteger)a3 << 192);
            (joined == (v + two256 - pR1) % two256).IsTrue();

            (P256R1Curve.GteP(r0, r1, r2, r3) == (v >= pR1)).IsTrue();

            (a0, a1, a2, a3) = (r0, r1, r2, r3);
            P256K1Curve.SubtractP(ref a0, ref a1, ref a2, ref a3);
            joined = a0 | ((BigInteger)a1 << 64) | ((BigInteger)a2 << 128) | ((BigInteger)a3 << 192);
            (joined == (v + two256 - pK1) % two256).IsTrue();
        }
    }

    /// <summary>
    /// Field operations verified against <see cref="BigInteger"/>, including square roots.
    /// </summary>
    [Fact]
    public void FieldOps_MatchBigInteger()
    {
        var rng = new Random(777);
        var curves = new ECCurveBase[] { P256K1Curve.Instance, P256R1Curve.Instance };
        var x = new uint[8];
        var y = new uint[8];
        var z = new uint[8];

        foreach (var curve in curves)
        {
            var q = ToBig(curve.UIntQ);

            void NextMod(uint[] a)
            {
                while (true)
                {
                    for (var i = 0; i < a.Length; i++)
                    {
                        a[i] = (uint)rng.Next() ^ ((uint)rng.Next() << 16);
                    }

                    if (ToBig(a) < q)
                    {
                        return;
                    }
                }
            }

            for (var i = 0; i < 300; i++)
            {
                NextMod(x);
                NextMod(y);

                curve.ElementMultiply(x, y, z);
                (ToBig(z) == (ToBig(x) * ToBig(y)) % q).IsTrue();

                curve.ElementSquare(x, z);
                (ToBig(z) == (ToBig(x) * ToBig(x)) % q).IsTrue();

                curve.ElementAdd(x, y, z);
                (ToBig(z) == (ToBig(x) + ToBig(y)) % q).IsTrue();

                curve.ElementNegate(x, z);
                (ToBig(z) == (q - ToBig(x)) % q).IsTrue();

                // sqrt of a square must succeed and square back to the same value
                curve.ElementSquare(x, y);
                curve.ElementSqrt(y, z).IsTrue();
                curve.ElementSquare(z, z);
                y.AsSpan().SequenceEqual(z).IsTrue();
            }
        }
    }
}
