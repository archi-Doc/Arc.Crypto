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

    private const uint P7 = 0xFFFFFFFF;

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
        // memory is touched only on entry and exit. The square body is Nat256.Square64, pasted
        // because address-taken out parameters of a helper defeat register promotion in RyuJIT.
        // The reduction is the word-based chain of Reduce/Reduce32/AddPInvTo operating on 32-bit
        // halves extracted from the limbs, with the carry-skipping shortcuts of Reduce32 and
        // AddPInvTo expanded unconditionally (adding zero words is a no-op, so this is identical).
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

            // ---- reduce: (q0..q7) -> (r0..r3), same arithmetic as Reduce ----
            long xx08 = (long)(uint)q4 - 6;
            long xx09 = (long)(q4 >> 32);
            long xx10 = (long)(uint)q5;
            long xx11 = (long)(q5 >> 32);
            long xx12 = (long)(uint)q6;
            long xx13 = (long)(q6 >> 32);
            long xx14 = (long)(uint)q7;
            long xx15 = (long)(q7 >> 32);

            long t0 = xx08 + xx09;
            long t1 = xx09 + xx10;
            long t2 = xx10 + xx11 - xx15;
            long t3 = xx11 + xx12;
            long t4 = xx12 + xx13;
            long t5 = xx13 + xx14;
            long t6 = xx14 + xx15;
            long t7 = t5 - t0;

            long cc = 0;
            cc += (long)(uint)q0 - t3 - t7;
            uint w0 = (uint)cc;
            cc >>= 32;
            cc += (long)(q0 >> 32) + t1 - t4 - t6;
            uint w1 = (uint)cc;
            cc >>= 32;
            cc += (long)(uint)q1 + t2 - t5;
            uint w2 = (uint)cc;
            cc >>= 32;
            cc += (long)(q1 >> 32) + (t3 << 1) + t7 - t6;
            uint w3 = (uint)cc;
            cc >>= 32;
            cc += (long)(uint)q2 + (t4 << 1) + xx14 - t1;
            uint w4 = (uint)cc;
            cc >>= 32;
            cc += (long)(q2 >> 32) + (t5 << 1) - t2;
            uint w5 = (uint)cc;
            cc >>= 32;
            cc += (long)(uint)q3 + (t6 << 1) + t7;
            uint w6 = (uint)cc;
            cc >>= 32;
            cc += (long)(q3 >> 32) + (xx15 << 1) + xx08 - t2 - t4;
            uint w7 = (uint)cc;
            cc >>= 32;
            cc += 6;

            Debug.Assert(cc >= 0);

            // ---- Reduce32(cc): fold the small top word (unconditional form) ----
            long v = (uint)cc;
            long cc2 = (long)w0 + v;
            w0 = (uint)cc2;
            cc2 >>= 32;
            cc2 += (long)w1;
            w1 = (uint)cc2;
            cc2 >>= 32;
            cc2 += (long)w2;
            w2 = (uint)cc2;
            cc2 >>= 32;
            cc2 += (long)w3 - v;
            w3 = (uint)cc2;
            cc2 >>= 32;
            cc2 += (long)w4;
            w4 = (uint)cc2;
            cc2 >>= 32;
            cc2 += (long)w5;
            w5 = (uint)cc2;
            cc2 >>= 32;
            cc2 += (long)w6 - v;
            w6 = (uint)cc2;
            cc2 >>= 32;
            cc2 += (long)w7 + v;
            w7 = (uint)cc2;
            cc2 >>= 32;

            Debug.Assert(cc2 == 0 || cc2 == 1);

            r0 = w0 | ((ulong)w1 << 32);
            r1 = w2 | ((ulong)w3 << 32);
            r2 = w4 | ((ulong)w5 << 32);
            r3 = w6 | ((ulong)w7 << 32);

            if (cc2 != 0 || GteP(r0, r1, r2, r3))
            {
                AddPInv(ref r0, ref r1, ref r2, ref r3);
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
    /// Determines whether the value is greater than or equal to <c>p</c> (limbs least significant first).
    /// </summary>
    /// <param name="r0">Limb 0 (least significant).</param>
    /// <param name="r1">Limb 1.</param>
    /// <param name="r2">Limb 2.</param>
    /// <param name="r3">Limb 3 (most significant).</param>
    /// <returns><see langword="true"/> if the value is greater than or equal to <c>p</c>; otherwise, <see langword="false"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static bool GteP(ulong r0, ulong r1, ulong r2, ulong r3)
    {
        const ulong L3 = 0xFFFFFFFF00000001UL;
        const ulong L2 = 0x0000000000000000UL;
        const ulong L1 = 0x00000000FFFFFFFFUL;

        if (r3 != L3)
        {
            return r3 > L3;
        }

        if (r2 != L2)
        {
            return r2 > L2;
        }

        if (r1 != L1)
        {
            return r1 > L1;
        }

        return r0 == ulong.MaxValue;
    }

    /// <summary>
    /// Adds <c>2^256 - p</c> and discards the carry out of 2^256, i.e. subtracts <c>p</c> once.
    /// The 64-bit limb counterpart of <see cref="AddPInvTo"/>. Cold path (probability about 2^-32
    /// per reduction), kept out of line and shared so that it can be unit-tested directly.
    /// </summary>
    /// <param name="r0">Limb 0 (least significant).</param>
    /// <param name="r1">Limb 1.</param>
    /// <param name="r2">Limb 2.</param>
    /// <param name="r3">Limb 3 (most significant).</param>
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static void AddPInv(ref ulong r0, ref ulong r1, ref ulong r2, ref ulong r3)
    {
        // 2^256 - p = 2^224 - 2^192 - 2^96 + 1, i.e. words {1, 0, 0, -1, 0, 0, -1, 1}.
        long cc = (long)(uint)r0 + 1;
        uint w0 = (uint)cc;
        cc >>= 32;
        cc += (long)(uint)(r0 >> 32);
        uint w1 = (uint)cc;
        cc >>= 32;
        cc += (long)(uint)r1;
        uint w2 = (uint)cc;
        cc >>= 32;
        cc += (long)(uint)(r1 >> 32) - 1;
        uint w3 = (uint)cc;
        cc >>= 32;
        cc += (long)(uint)r2;
        uint w4 = (uint)cc;
        cc >>= 32;
        cc += (long)(uint)(r2 >> 32);
        uint w5 = (uint)cc;
        cc >>= 32;
        cc += (long)(uint)r3 - 1;
        uint w6 = (uint)cc;
        cc >>= 32;
        cc += (long)(uint)(r3 >> 32) + 1;
        uint w7 = (uint)cc;

        r0 = w0 | ((ulong)w1 << 32);
        r1 = w2 | ((ulong)w3 << 32);
        r2 = w4 | ((ulong)w5 << 32);
        r3 = w6 | ((ulong)w7 << 32);
    }

    /// <summary>
    /// Portable word-based repeated squaring, used on big-endian platforms.
    /// </summary>
    private static void ElementSquareNSoft(ReadOnlySpan<uint> x, int n, Span<uint> z)
    {
        scoped Span<uint> tt = stackalloc uint[P256UIntLength * 2];
        Nat256.Square(x, tt);
        Reduce(tt, z);

        while (--n > 0)
        {
            Nat256.Square(z, tt);
            Reduce(tt, z);
        }
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
