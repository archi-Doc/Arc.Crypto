// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto.EC;

#pragma warning disable SA1202 // Elements should be ordered by access (fast paths are kept next to their portable fallbacks)
#pragma warning disable SA1203
#pragma warning disable SA1405 // Debug.Assert should provide message text

/// <summary>
/// The secp256k1 elliptic curve, as used by Bitcoin and other systems.
/// </summary>
public class P256K1Curve : ECCurveBase
{
    /// <summary>
    /// The number of 32-bit words in a field element.
    /// </summary>
    public const int P256UIntLength = 8;

    /// <summary>
    /// The field prime, as a big-endian hexadecimal string.
    /// </summary>
    public const string HexQ = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

    /// <summary>
    /// The curve coefficient <c>a</c>, as a big-endian hexadecimal string.
    /// </summary>
    public const string HexA = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>
    /// The curve coefficient <c>b</c>, as a big-endian hexadecimal string.
    /// </summary>
    public const string HexB = "0000000000000000000000000000000000000000000000000000000000000007";

    /// <summary>
    /// The order of the base point, as a big-endian hexadecimal string.
    /// </summary>
    public const string HexOrder = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    /// <summary>
    /// The shared instance of the secp256k1 curve.
    /// </summary>
    public static readonly P256K1Curve Instance = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="P256K1Curve"/> class.
    /// </summary>
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

    /// <inheritdoc/>
    public override string CurveName => "secp256k1";

    /// <inheritdoc/>
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
            Nat.Add33To(8, PInv33, z);
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

    /// <inheritdoc/>
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

    internal static void ElementSquareN(ReadOnlySpan<uint> x, int n, Span<uint> z)
    {
        Debug.Assert(n > 0);

        if (!BitConverter.IsLittleEndian)
        {
            ElementSquareNSoft(x, n, z);
            return;
        }

        // The value stays in four 64-bit registers across all n square-and-reduce rounds;
        // memory is touched only on entry and exit. The square body is Nat256.Square64 and the
        // reduction body is Reduce64, both pasted (see the comment in Reduce64 on why).
        ReadOnlySpan<ulong> xd = MemoryMarshal.Cast<uint, ulong>(x);
        ulong r3 = xd[3], r2 = xd[2], r1 = xd[1], r0 = xd[0];

        do
        {
            // ---- square: (r0..r3) -> (q0..q7) ----
            UInt128 c = (UInt128)r0 * r1;
            ulong q1 = (ulong)c;
            c >>= 64;
            c += (UInt128)r0 * r2;
            ulong q2 = (ulong)c;
            c >>= 64;
            c += (UInt128)r0 * r3;
            ulong q3 = (ulong)c;
            ulong q4 = (ulong)(c >> 64);

            c = ((UInt128)r1 * r2) + q3;
            q3 = (ulong)c;
            c >>= 64;
            c += ((UInt128)r1 * r3) + q4;
            q4 = (ulong)c;
            ulong q5 = (ulong)(c >> 64);

            c = ((UInt128)r2 * r3) + q5;
            q5 = (ulong)c;
            ulong q6 = (ulong)(c >> 64);

            ulong q7 = q6 >> 63;
            q6 = (q6 << 1) | (q5 >> 63);
            q5 = (q5 << 1) | (q4 >> 63);
            q4 = (q4 << 1) | (q3 >> 63);
            q3 = (q3 << 1) | (q2 >> 63);
            q2 = (q2 << 1) | (q1 >> 63);
            q1 <<= 1;

            c = (UInt128)r0 * r0;
            ulong q0 = (ulong)c;
            c = (c >> 64) + q1;
            q1 = (ulong)c;
            c = ((UInt128)r1 * r1) + (ulong)(c >> 64) + q2;
            q2 = (ulong)c;
            c = (c >> 64) + q3;
            q3 = (ulong)c;
            c = ((UInt128)r2 * r2) + (ulong)(c >> 64) + q4;
            q4 = (ulong)c;
            c = (c >> 64) + q5;
            q5 = (ulong)c;
            c = ((UInt128)r3 * r3) + (ulong)(c >> 64) + q6;
            q6 = (ulong)c;
            q7 += (ulong)(c >> 64);

            // ---- reduce: (q0..q7) -> (r0..r3) ----
            UInt128 t = ((UInt128)q4 * C) + q0;
            r0 = (ulong)t;
            t >>= 64;
            t += ((UInt128)q5 * C) + q1;
            r1 = (ulong)t;
            t >>= 64;
            t += ((UInt128)q6 * C) + q2;
            r2 = (ulong)t;
            t >>= 64;
            t += ((UInt128)q7 * C) + q3;
            r3 = (ulong)t;
            ulong r4 = (ulong)(t >> 64);

            t = ((UInt128)r4 * C) + r0;
            r0 = (ulong)t;
            t = (t >> 64) + r1;
            r1 = (ulong)t;
            t = (t >> 64) + r2;
            r2 = (ulong)t;
            t = (t >> 64) + r3;
            r3 = (ulong)t;

            if ((t >> 64) != 0 || (r3 == ulong.MaxValue && r2 == ulong.MaxValue && r1 == ulong.MaxValue && r0 >= P0))
            {
                SubtractP(ref r0, ref r1, ref r2, ref r3);
            }
        }
        while (--n > 0);

        Span<ulong> zd = MemoryMarshal.Cast<uint, ulong>(z);
        zd[3] = r3;
        zd[2] = r2;
        zd[1] = r1;
        zd[0] = r0;
    }

    /// <summary>
    /// Portable word-based repeated squaring, used on big-endian platforms.
    /// </summary>
    private static void ElementSquareNSoft(ReadOnlySpan<uint> x, int n, Span<uint> z)
    {
        scoped Span<uint> tmp = stackalloc uint[P256UIntLength * 2];
        Nat256.Square(x, tmp);
        Reduce(tmp, z);

        while (--n > 0)
        {
            Nat256.Square(z, tmp);
            Reduce(tmp, z);
        }
    }

    internal static void Reduce(ReadOnlySpan<uint> xx, Span<uint> z)
    {
        if (BitConverter.IsLittleEndian)
        {
            Reduce64(xx, z);
        }
        else
        {
            ReduceSoft(xx, z);
        }
    }

    /// <summary>
    /// Reduction on 64-bit limbs. With <c>p = 2^256 - c</c> (<c>c = 0x1000003D1</c>),
    /// a 512-bit value <c>hi * 2^256 + lo</c> is congruent to <c>hi * c + lo</c>;
    /// one such fold shrinks the value to 257+ bits, a second fold of the tiny top limb
    /// and at most one conditional subtraction of <c>p</c> (implemented as adding <c>c</c>)
    /// bring it into <c>[0, p)</c>. Little-endian only.
    /// </summary>
    private static void Reduce64(ReadOnlySpan<uint> xx, Span<uint> z)
    {
        ReadOnlySpan<ulong> xd = MemoryMarshal.Cast<uint, ulong>(xx);
        Span<ulong> zd = MemoryMarshal.Cast<uint, ulong>(z);

        ulong q7 = xd[7], q6 = xd[6], q5 = xd[5], q4 = xd[4];
        ulong q3 = xd[3], q2 = xd[2], q1 = xd[1], q0 = xd[0];

        // First fold: z = lo + hi * c. No overflow: product + limb + carry stays far below 2^128.
        // This body is repeated inside ElementSquareN; keep the copies in sync (helper extraction
        // is avoided because address-taken out parameters defeat register promotion in RyuJIT).
        UInt128 t = ((UInt128)q4 * C) + q0;
        ulong z0 = (ulong)t;
        t >>= 64;
        t += ((UInt128)q5 * C) + q1;
        ulong z1 = (ulong)t;
        t >>= 64;
        t += ((UInt128)q6 * C) + q2;
        ulong z2 = (ulong)t;
        t >>= 64;
        t += ((UInt128)q7 * C) + q3;
        ulong z3 = (ulong)t;
        ulong z4 = (ulong)(t >> 64); // < 2^34

        // Second fold: absorb the small top limb.
        t = ((UInt128)z4 * C) + z0;
        z0 = (ulong)t;
        t = (t >> 64) + z1;
        z1 = (ulong)t;
        t = (t >> 64) + z2;
        z2 = (ulong)t;
        t = (t >> 64) + z3;
        z3 = (ulong)t;

        // At most one subtraction of p is needed. When the fold carried out of 2^256 the wrapped
        // value is tiny, so the two conditions are mutually exclusive and a single correction suffices.
        if ((t >> 64) != 0 || (z3 == ulong.MaxValue && z2 == ulong.MaxValue && z1 == ulong.MaxValue && z0 >= P0))
        {
            SubtractP(ref z0, ref z1, ref z2, ref z3);
        }

        zd[3] = z3;
        zd[2] = z2;
        zd[1] = z1;
        zd[0] = z0;
    }

    /// <summary>
    /// Subtracts <c>p</c> once, implemented as adding <c>2^256 - p</c> and discarding the carry out of 2^256.
    /// Cold path: reachable only with probability about 2^-32 per reduction, so it is kept out of line
    /// and shared between the span-based and the fused reductions (which also makes it directly unit-testable).
    /// </summary>
    /// <param name="z0">Limb 0 (least significant).</param>
    /// <param name="z1">Limb 1.</param>
    /// <param name="z2">Limb 2.</param>
    /// <param name="z3">Limb 3 (most significant).</param>
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static void SubtractP(ref ulong z0, ref ulong z1, ref ulong z2, ref ulong z3)
    {
        UInt128 t = (UInt128)z0 + C;
        z0 = (ulong)t;
        t = (t >> 64) + z1;
        z1 = (ulong)t;
        t = (t >> 64) + z2;
        z2 = (ulong)t;
        z3 += (ulong)(t >> 64);
    }

    private const ulong C = 0x1000003D1UL; // 2^256 - p
    private const ulong P0 = 0xFFFFFFFEFFFFFC2FUL; // lowest 64-bit limb of p; the upper three are all ones.

    /// <summary>
    /// Portable 32-bit word reduction, used on big-endian platforms.
    /// </summary>
    /// <param name="xx">The 512-bit input as sixteen 32-bit words, least significant first.</param>
    /// <param name="z">Receives the reduced value as eight 32-bit words.</param>
    internal static void ReduceSoft(ReadOnlySpan<uint> xx, Span<uint> z)
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
