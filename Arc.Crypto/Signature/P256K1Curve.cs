// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;

namespace Arc.Crypto.EC;

#pragma warning disable SA1203
#pragma warning disable SA1405 // Debug.Assert should provide message text

public class P256K1Curve : ECCurveBase
{
    public const int P256UIntLength = 8;
    public const string HexQ = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    public const string HexA = "0000000000000000000000000000000000000000000000000000000000000000";
    public const string HexB = "0000000000000000000000000000000000000000000000000000000000000007";
    public const string HexOrder = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    public static readonly P256K1Curve Instance = new();

    public P256K1Curve()
        : base(P256UIntLength, HexQ, HexA, HexB, HexOrder)
    {
    }

    private static readonly uint[] P = new uint[]
    {
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    };

    private const uint P7 = 0xFFFFFFFF;
    private const uint PInv33 = 0x3D1;

    public override string CurveName => "secp256k1";

    public override int ElementIsZero(ReadOnlySpan<uint> x)
    {
        uint d = 0;
        for (int i = 0; i < 8; ++i)
        {
            d |= x[i];
        }

        d = (d >> 1) | (d & 1);
        return ((int)d - 1) >> 31;
    }

    public override void ElementSquare(ReadOnlySpan<uint> x, Span<uint> z)
    {
        scoped Span<uint> tmp = stackalloc uint[this.UIntLength * 2];
        Nat256.Square(x, tmp);
        Reduce(tmp, z);
    }

    public override void ElementAdd(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
    {
        uint c = Nat256.Add(x, y, z);
        if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
        {
            Nat.Add33To(8, PInv33, z);
        }
    }

    public override void ElementMultiply(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
    {
        scoped Span<uint> tmp = stackalloc uint[this.UIntLength * 2];
        Nat256.Mul(x, y, tmp);
        Reduce(tmp, z);
    }

    public override bool ElementSqrt(ReadOnlySpan<uint> x1, Span<uint> z)
    {
        if (Nat256.IsZero(x1) || Nat256.IsOne(x1))
        {
            x1.CopyTo(z);
            return true;
        }

        scoped Span<uint> x2 = stackalloc uint[this.UIntLength];
        scoped Span<uint> x3 = stackalloc uint[this.UIntLength];
        scoped Span<uint> x6 = stackalloc uint[this.UIntLength];

        this.ElementSquare(x1, x2);
        this.ElementMultiply(x2, x1, x2);
        this.ElementSquare(x2, x3);
        this.ElementMultiply(x3, x1, x3);
        ElementSquareN(x3, 3, x6);
        this.ElementMultiply(x6, x3, x6);
        var x9 = x6;
        ElementSquareN(x6, 3, x9);
        this.ElementMultiply(x9, x3, x9);
        var x11 = x9;
        ElementSquareN(x9, 2, x11);
        this.ElementMultiply(x11, x2, x11);
        scoped Span<uint> x22 = stackalloc uint[this.UIntLength];
        ElementSquareN(x11, 11, x22);
        this.ElementMultiply(x22, x11, x22);
        var x44 = x11;
        ElementSquareN(x22, 22, x44);
        this.ElementMultiply(x44, x22, x44);
        scoped Span<uint> x88 = stackalloc uint[this.UIntLength];
        ElementSquareN(x44, 44, x88);
        this.ElementMultiply(x88, x44, x88);
        scoped Span<uint> x176 = stackalloc uint[this.UIntLength];
        ElementSquareN(x88, 88, x176);
        this.ElementMultiply(x176, x88, x176);
        var x220 = x88;
        ElementSquareN(x176, 44, x220);
        this.ElementMultiply(x220, x44, x220);
        var x223 = x44;
        ElementSquareN(x220, 3, x223);
        this.ElementMultiply(x223, x3, x223);

        var t1 = x223;
        ElementSquareN(t1, 23, t1);
        this.ElementMultiply(t1, x22, t1);
        ElementSquareN(t1, 6, t1);
        this.ElementMultiply(t1, x2, t1);
        ElementSquareN(t1, 2, t1);

        var t2 = x2;
        this.ElementSquare(t1, t2);

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

    public override void ElementNegate(ReadOnlySpan<uint> x, Span<uint> z)
    {
        if (this.ElementIsZero(x) != 0)
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

        scoped Span<uint> tmp = stackalloc uint[P256UIntLength * 2];
        Nat256.Square(x, tmp);
        Reduce(tmp, z);

        while (--n > 0)
        {
            Nat256.Square(z, tmp);
            Reduce(tmp, z);
        }
    }

    private static void Reduce(ReadOnlySpan<uint> xx, Span<uint> z)
    {
        ulong cc = Nat256.Mul33Add(PInv33, xx, 8, xx, 0, z, 0);
        uint c = Nat256.Mul33DWordAdd(PInv33, cc, z, 0);

        Debug.Assert(c == 0 || c == 1);

        if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
        {
            Nat.Add33To(8, PInv33, z);
        }
    }
}
