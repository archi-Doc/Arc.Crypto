// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;

namespace Arc.Crypto.EC;

#pragma warning disable SA1203
#pragma warning disable SA1405 // Debug.Assert should provide message text

/// <summary>
/// The secp256r1 (NIST P-256) elliptic curve.
/// </summary>
public class P256R1Curve : ECCurveBase
{
    /// <summary>
    /// The number of 32-bit words in a field element.
    /// </summary>
    public const int P256UIntLength = 8;

    /// <summary>
    /// The field prime, as a big-endian hexadecimal string.
    /// </summary>
    public const string HexQ = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";

    /// <summary>
    /// The curve coefficient <c>a</c>, as a big-endian hexadecimal string.
    /// </summary>
    public const string HexA = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";

    /// <summary>
    /// The curve coefficient <c>b</c>, as a big-endian hexadecimal string.
    /// </summary>
    public const string HexB = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";

    /// <summary>
    /// The order of the base point, as a big-endian hexadecimal string.
    /// </summary>
    public const string HexOrder = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

    /// <summary>
    /// The shared instance of the secp256r1 curve.
    /// </summary>
    public static readonly P256R1Curve Instance = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="P256R1Curve"/> class.
    /// </summary>
    public P256R1Curve()
        : base(P256UIntLength, HexQ, HexA, HexB, HexOrder)
    {
    }

    private static readonly uint[] P = new uint[]
    {
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
    };

    private static readonly uint[] PExt = new uint[]
    {
        0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0x00000001, 0xFFFFFFFE, 0x00000002, 0xFFFFFFFE,
    };

    private const uint P7 = 0xFFFFFFFF;
    private const uint PExt15 = 0xFFFFFFFE;

    /// <inheritdoc/>
    public override string CurveName => "secp256r1";

    /// <inheritdoc/>
    public override int ElementIsZero(ReadOnlySpan<uint> x)
    {
        uint d = 0;
        for (var i = 0; i < 8; ++i)
        {
            d |= x[i];
        }

        d = (d >> 1) | (d & 1);
        return ((int)d - 1) >> 31;
    }

    /// <inheritdoc/>
    public override void ElementSquare(ReadOnlySpan<uint> x, Span<uint> z)
    {
        scoped Span<uint> tmp = stackalloc uint[this.UIntLength * 2];
        Nat256.Square(x, tmp);
        Reduce(tmp, z);
    }

    /// <inheritdoc/>
    public override void ElementAdd(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
    {
        uint c = Nat256.Add(x, y, z);
        if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
        {
            AddPInvTo(z);
        }
    }

    /// <inheritdoc/>
    public override void ElementMultiply(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
    {
        scoped Span<uint> tmp = stackalloc uint[this.UIntLength * 2];
        Nat256.Mul(x, y, tmp);
        Reduce(tmp, z);
    }

    /// <inheritdoc/>
    public override bool ElementSqrt(ReadOnlySpan<uint> x1, Span<uint> z)
    {
        if (Nat256.IsZero(x1) || Nat256.IsOne(x1))
        {
            x1.CopyTo(z);
            return true;
        }

        scoped Span<uint> t1 = stackalloc uint[this.UIntLength];
        scoped Span<uint> t2 = stackalloc uint[this.UIntLength];

        this.ElementSquare(x1, t1);
        this.ElementMultiply(t1, x1, t1);

        ElementSquareN(t1, 2, t2);
        this.ElementMultiply(t2, t1, t2);

        ElementSquareN(t2, 4, t1);
        this.ElementMultiply(t1, t2, t1);

        ElementSquareN(t1, 8, t2);
        this.ElementMultiply(t2, t1, t2);

        ElementSquareN(t2, 16, t1);
        this.ElementMultiply(t1, t2, t1);

        ElementSquareN(t1, 32, t1);
        this.ElementMultiply(t1, x1, t1);

        ElementSquareN(t1, 96, t1);
        this.ElementMultiply(t1, x1, t1);

        ElementSquareN(t1, 94, t1);
        this.ElementMultiply(t1, t1, t2);

        if (x1.SequenceEqual(t2))
        {
            t1.CopyTo(z);
            return true;
        }
        else
        {
            return false;
        }
    }

    /// <inheritdoc/>
    public override void ElementNegate(ReadOnlySpan<uint> x, Span<uint> z)
    {
        if (IsZero(x) != 0)
        {
            Nat256.Sub(P, P, z);
        }
        else
        {
            Nat256.Sub(P, x, z);
        }
    }

    private static void ElementSquareN(ReadOnlySpan<uint> x, int n, Span<uint> z)
    {
        Debug.Assert(n > 0);

        scoped Span<uint> tt = stackalloc uint[P256UIntLength * 2];
        Nat256.Square(x, tt);
        Reduce(tt, z);

        while (--n > 0)
        {
            Nat256.Square(z, tt);
            Reduce(tt, z);
        }
    }

    private static int IsZero(ReadOnlySpan<uint> x)
    {
        uint d = 0;
        for (int i = 0; i < 8; ++i)
        {
            d |= x[i];
        }

        d = (d >> 1) | (d & 1);
        return ((int)d - 1) >> 31;
    }

    private static void AddPInvTo(Span<uint> z)
    {
        long c = (long)z[0] + 1;
        z[0] = (uint)c;
        c >>= 32;
        if (c != 0)
        {
            c += (long)z[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (long)z[2];
            z[2] = (uint)c;
            c >>= 32;
        }

        c += (long)z[3] - 1;
        z[3] = (uint)c;
        c >>= 32;
        if (c != 0)
        {
            c += (long)z[4];
            z[4] = (uint)c;
            c >>= 32;
            c += (long)z[5];
            z[5] = (uint)c;
            c >>= 32;
        }

        c += (long)z[6] - 1;
        z[6] = (uint)c;
        c >>= 32;
        c += (long)z[7] + 1;
        z[7] = (uint)c;
    }

    private static void Reduce(ReadOnlySpan<uint> xx, Span<uint> z)
    {
        long xx08 = xx[8], xx09 = xx[9], xx10 = xx[10], xx11 = xx[11];
        long xx12 = xx[12], xx13 = xx[13], xx14 = xx[14], xx15 = xx[15];

        const long n = 6;

        xx08 -= n;

        long t0 = xx08 + xx09;
        long t1 = xx09 + xx10;
        long t2 = xx10 + xx11 - xx15;
        long t3 = xx11 + xx12;
        long t4 = xx12 + xx13;
        long t5 = xx13 + xx14;
        long t6 = xx14 + xx15;
        long t7 = t5 - t0;

        long cc = 0;
        cc += (long)xx[0] - t3 - t7;
        z[0] = (uint)cc;
        cc >>= 32;
        cc += (long)xx[1] + t1 - t4 - t6;
        z[1] = (uint)cc;
        cc >>= 32;
        cc += (long)xx[2] + t2 - t5;
        z[2] = (uint)cc;
        cc >>= 32;
        cc += (long)xx[3] + (t3 << 1) + t7 - t6;
        z[3] = (uint)cc;
        cc >>= 32;
        cc += (long)xx[4] + (t4 << 1) + xx14 - t1;
        z[4] = (uint)cc;
        cc >>= 32;
        cc += (long)xx[5] + (t5 << 1) - t2;
        z[5] = (uint)cc;
        cc >>= 32;
        cc += (long)xx[6] + (t6 << 1) + t7;
        z[6] = (uint)cc;
        cc >>= 32;
        cc += (long)xx[7] + (xx15 << 1) + xx08 - t2 - t4;
        z[7] = (uint)cc;
        cc >>= 32;
        cc += n;

        Debug.Assert(cc >= 0);

        Reduce32((uint)cc, z);
    }

    private static void Reduce32(uint x, Span<uint> z)
    {
        long cc = 0;

        if (x != 0)
        {
            long xx08 = x;

            cc += (long)z[0] + xx08;
            z[0] = (uint)cc;
            cc >>= 32;
            if (cc != 0)
            {
                cc += (long)z[1];
                z[1] = (uint)cc;
                cc >>= 32;
                cc += (long)z[2];
                z[2] = (uint)cc;
                cc >>= 32;
            }

            cc += (long)z[3] - xx08;
            z[3] = (uint)cc;
            cc >>= 32;
            if (cc != 0)
            {
                cc += (long)z[4];
                z[4] = (uint)cc;
                cc >>= 32;
                cc += (long)z[5];
                z[5] = (uint)cc;
                cc >>= 32;
            }

            cc += (long)z[6] - xx08;
            z[6] = (uint)cc;
            cc >>= 32;
            cc += (long)z[7] + xx08;
            z[7] = (uint)cc;
            cc >>= 32;

            Debug.Assert(cc == 0 || cc == 1);
        }

        if (cc != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
        {
            AddPInvTo(z);
        }
    }
}
