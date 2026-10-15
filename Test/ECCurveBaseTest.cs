// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Numerics;
using Arc.Crypto;
using Arc.Crypto.EC;
using Xunit;

namespace Test;

/// <summary>
/// Tests for <see cref="ECCurveBase"/>: constructor validation, seed validation and point compression,
/// checked against published points and <see cref="BigInteger"/> arithmetic.
/// </summary>
public class ECCurveBaseTest
{
    // secp256k1 base point G, SEC 2 v2.0 section 2.4.1 (uncompressed form 04 || Gx || Gy).
    private const string K1Gx = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    private const string K1Gy = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    // secp256r1 (P-256) base point G, SEC 2 v2.0 section 2.4.2 / FIPS 186-4 D.1.2.3.
    private const string R1Gx = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    private const string R1Gy = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";

    // RFC 6979 A.2.5 (ECDSA, 256 bits, prime field): private key x and public key U = xG on P-256.
    private const string Rfc6979Key = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    private const string Rfc6979Ux = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    private const string Rfc6979Uy = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

    private static readonly ECCurveBase[] Curves = [Secp256k1Curve.Instance, Secp256r1Curve.Instance];

    public static TheoryData<string, string, string> KnownPoints => new()
    {
        { "secp256k1", K1Gx, K1Gy },
        { "secp256r1", R1Gx, R1Gy },
        { "secp256r1", Rfc6979Ux, Rfc6979Uy },
    };

    [Fact]
    public void Constructor_AcceptsFullLengthParameters()
    {
        var curve = new MinimalCurve(Secp256k1Curve.HexQ, Secp256k1Curve.HexA, Secp256k1Curve.HexB, Secp256k1Curve.HexOrder);
        curve.ByteLength.Is(32);
        curve.ByteQ.Is(Secp256k1Curve.Instance.ByteQ);
        curve.UIntQ.Is(Secp256k1Curve.Instance.UIntQ);
        curve.UIntA.Length.Is(8);
        curve.UIntB.Is(Secp256k1Curve.Instance.UIntB);
        curve.UIntOrder.Is(Secp256k1Curve.Instance.UIntOrder);

        // Lower-case digits are accepted.
        new MinimalCurve(Secp256r1Curve.HexQ.ToLowerInvariant(), Secp256r1Curve.HexA, Secp256r1Curve.HexB, Secp256r1Curve.HexOrder).UIntQ.Is(Secp256r1Curve.Instance.UIntQ);
    }

    [Fact]
    public void Constructor_RejectsWrongParameterLengths()
    {
        var q = Secp256k1Curve.HexQ;
        var a = Secp256k1Curve.HexA;
        var b = Secp256k1Curve.HexB;
        var order = Secp256k1Curve.HexOrder;

        // Short forms used to be truncated silently (an empty UIntB made DecompressY throw later).
        Assert.Throws<ArgumentException>(() => new MinimalCurve(q, a, "07", order)).ParamName.Is("hexB");
        Assert.Throws<ArgumentException>(() => new MinimalCurve(q[2..], a, b, order)).ParamName.Is("hexQ");
        Assert.Throws<ArgumentException>(() => new MinimalCurve(q, a[1..], b, order)).ParamName.Is("hexA"); // odd length
        Assert.Throws<ArgumentException>(() => new MinimalCurve(q, a, b, "01" + order)).ParamName.Is("hexOrder"); // overlong
        Assert.Throws<ArgumentException>(() => new MinimalCurve(q, a, b, order + "00")).ParamName.Is("hexOrder");
        Assert.Throws<ArgumentException>(() => new MinimalCurve(q, a, b, string.Empty)).ParamName.Is("hexOrder");
        Assert.Throws<ArgumentException>(() => new MinimalCurve(7, q, a, b, order)).ParamName.Is("hexQ"); // 7 words = 56 digits

        Assert.Throws<ArgumentNullException>(() => new MinimalCurve(q, a, null!, order)).ParamName.Is("hexB");
        Assert.Throws<ArgumentOutOfRangeException>(() => new MinimalCurve(0, q, a, b, order));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MinimalCurve(-1, q, a, b, order));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MinimalCurve((int.MaxValue / 32) + 1, q, a, b, order));
        Assert.Throws<FormatException>(() => new MinimalCurve(q, a, b, order[..^2] + "4G"));
    }

    [Theory]
    [MemberData(nameof(KnownPoints))]
    public void DecompressY_KnownPoints(string curveName, string hexX, string hexY)
    {
        var curve = GetCurve(curveName);
        var p = ToBig(curve.ByteQ);
        var x = Hex.FromStringToByteArray(hexX);
        var y = Hex.FromStringToByteArray(hexY);
        var bit = curve.CompressY(y);
        bit.Is((uint)(y[^1] & 1));

        curve.DecompressY(x, bit).Is(y);
        curve.DecompressY(x, bit + 2).Is(y); // only the least significant bit is used
        curve.DecompressY(x, bit | 0xFFFFFFFE).Is(y);

        var other = curve.DecompressY(x, bit ^ 1);
        other!.Length.Is(curve.ByteLength);
        ToBig(other).Is(p - ToBig(y)); // the other root is -y
        curve.CompressY(other).Is(bit ^ 1);
    }

    [Fact]
    public void DecompressY_RejectsWrongLengths()
    {
        foreach (var curve in Curves)
        {
            var x = Hex.FromStringToByteArray(curve is Secp256k1Curve ? K1Gx : R1Gx);
            curve.DecompressY(x, 0).IsNotNull();

            curve.DecompressY(x.AsSpan(1), 0).IsNull();
            curve.DecompressY(x.AsSpan(0, 31), 0).IsNull();
            curve.DecompressY([0x00, .. x], 0).IsNull(); // a padded encoding of a valid x
            curve.DecompressY([.. x, 0x00], 1).IsNull();
            curve.DecompressY(ReadOnlySpan<byte>.Empty, 0).IsNull();
            curve.DecompressY(new byte[31], 0).IsNull();
            curve.CompressY(ReadOnlySpan<byte>.Empty).Is(0u);
        }
    }

    [Fact]
    public void DecompressY_MatchesEulerCriterion()
    {
        var rng = new Random(6979);
        foreach (var curve in Curves)
        {
            var p = ToBig(curve.ByteQ);
            var a = ToBig(curve.ByteA);
            var b = ToBig(curve.ByteB);
            var onCurve = 0;
            var offCurve = 0;

            for (var i = 0; i < 200; i++)
            {
                var x = i < 100 ? new BigInteger(i) : i < 110 ? p - (i - 99) : RandomBelow(rng, p);
                var rhs = ((x * x * x) + (a * x) + b) % p;
                var expected = rhs.IsZero || BigInteger.ModPow(rhs, (p - 1) / 2, p).IsOne;

                var xBytes = ToBytes(x);
                var y0 = curve.DecompressY(xBytes, 0);
                var y1 = curve.DecompressY(xBytes, 1);
                (y0 is not null).Is(expected);
                (y1 is not null).Is(expected);
                if (y0 is null || y1 is null)
                {
                    offCurve++;
                    continue;
                }

                onCurve++;
                var v0 = ToBig(y0);
                var v1 = ToBig(y1);
                ((v0 * v0) % p).Is(rhs);
                v0.IsEven.IsTrue();
                ((v0 + v1) % p).IsZero.IsTrue();
                (v0 < p && v1 < p).IsTrue();
            }

            // Both paths, including the "not on the curve" null result, must have been taken.
            (onCurve > 40).IsTrue();
            (offCurve > 40).IsTrue();
        }

        // Fixed points off the curve: 7 is not a square modulo the secp256k1 prime, and x = 1 is not on P-256.
        Secp256k1Curve.Instance.DecompressY(new byte[32], 0).IsNull();
        Secp256k1Curve.Instance.DecompressY(new byte[32], 1).IsNull();
        Secp256r1Curve.Instance.DecompressY(ToBytes(BigInteger.One), 0).IsNull();
        Secp256r1Curve.Instance.DecompressY(ToBytes(BigInteger.One), 1).IsNull();
    }

    [Fact]
    public void IsValidSeed_KnownAnswersAndBoundaries()
    {
        // The RFC 6979 A.2.5 P-256 private key is a valid seed.
        Secp256r1Curve.Instance.IsValidSeed(Hex.FromStringToByteArray(Rfc6979Key)).IsTrue();

        foreach (var curve in Curves)
        {
            var order = ToBig(curve.ByteOrder);
            var two256 = BigInteger.One << 256;
            var lowWeight = new byte[32];
            lowWeight.AsSpan().Fill(0x01); // In range, but (3k) ^ k = 0x0202...02 has weight 32 < 64.
            curve.IsValidSeed(lowWeight).IsFalse();

            foreach (var value in new[]
            {
                BigInteger.Zero, BigInteger.One, order - 2, order - 1, order, order + 1, two256 - 1,
                ToBig(Hex.FromStringToByteArray(Rfc6979Key)), (two256 - 1) / 3, order >> 1, (order >> 1) + 1,
            })
            {
                var seed = ToBytes(value % two256);
                curve.IsValidSeed(seed).Is(IsValidReference(value % two256, order));
            }

            curve.IsValidSeed(ReadOnlySpan<byte>.Empty).IsFalse();
            curve.IsValidSeed(new byte[31]).IsFalse();
            curve.IsValidSeed(ToBytes(order - 1).AsSpan(1)).IsFalse();
            var longSeed = new byte[33];
            Hex.FromStringToByteArray(Rfc6979Key).CopyTo(longSeed, 1);
            curve.IsValidSeed(longSeed).IsFalse();
        }
    }

    [Fact]
    public void IsValidSeed_MatchesReferenceNearOrder()
    {
        // Seeds that share a long prefix with the order exercise every byte of the branch-free comparison.
        var rng = new Random(4141);
        foreach (var curve in Curves)
        {
            var order = ToBig(curve.ByteOrder);
            for (var i = 0; i < 2_000; i++)
            {
                var delta = RandomBelow(rng, BigInteger.One << rng.Next(1, 200));
                var value = (i & 1) == 0 ? order - delta : order + delta;
                if (value.Sign < 0 || value >= (BigInteger.One << 256))
                {
                    continue;
                }

                curve.IsValidSeed(ToBytes(value)).Is(IsValidReference(value, order));
            }
        }
    }

    private static ECCurveBase GetCurve(string name) => name == "secp256k1" ? Secp256k1Curve.Instance : Secp256r1Curve.Instance;

    private static bool IsValidReference(BigInteger value, BigInteger order)
        => value > 0 && value < order && BigInteger.PopCount((value * 3) ^ value) >= 64;

    private static BigInteger ToBig(ReadOnlySpan<byte> bigEndian) => new(bigEndian, isUnsigned: true, isBigEndian: true);

    private static byte[] ToBytes(BigInteger value)
    {
        var bytes = new byte[32];
        value.TryWriteBytes(bytes.AsSpan(32 - value.GetByteCount(isUnsigned: true)), out _, isUnsigned: true, isBigEndian: true).IsTrue();
        return bytes;
    }

    private static BigInteger RandomBelow(Random rng, BigInteger bound)
    {
        var bytes = new byte[(int)(bound.GetBitLength() / 8) + 9];
        rng.NextBytes(bytes);
        return new BigInteger(bytes, isUnsigned: true) % bound;
    }

    /// <summary>
    /// A derived curve with no field arithmetic, used to exercise the base constructor.
    /// </summary>
    private sealed class MinimalCurve : ECCurveBase
    {
        public MinimalCurve(string hexQ, string hexA, string hexB, string hexOrder)
            : this(8, hexQ, hexA, hexB, hexOrder)
        {
        }

        public MinimalCurve(int uintLength, string hexQ, string hexA, string hexB, string hexOrder)
            : base(uintLength, hexQ, hexA, hexB, hexOrder)
        {
        }

        public override string CurveName => "minimal";

        public override int ElementIsZero(ReadOnlySpan<uint> x) => throw new NotSupportedException();

        public override void ElementSquare(ReadOnlySpan<uint> x, Span<uint> z) => throw new NotSupportedException();

        public override void ElementAdd(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z) => throw new NotSupportedException();

        public override void ElementMultiply(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z) => throw new NotSupportedException();

        public override bool ElementSqrt(ReadOnlySpan<uint> x, Span<uint> z) => throw new NotSupportedException();

        public override void ElementNegate(ReadOnlySpan<uint> x, Span<uint> z) => throw new NotSupportedException();
    }
}
