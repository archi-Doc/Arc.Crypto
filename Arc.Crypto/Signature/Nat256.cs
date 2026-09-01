// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Arc.Crypto.EC;

#pragma warning disable SA1202 // Elements should be ordered by access (fast paths are kept next to their portable fallbacks)
#pragma warning disable SA1405 // Debug.Assert should provide message text

internal abstract class Nat256
{
    private const ulong M = 0xFFFFFFFFUL;

    public static uint Add(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
    {
        ulong c = 0;
        c += (ulong)x[0] + y[0];
        z[0] = (uint)c;
        c >>= 32;
        c += (ulong)x[1] + y[1];
        z[1] = (uint)c;
        c >>= 32;
        c += (ulong)x[2] + y[2];
        z[2] = (uint)c;
        c >>= 32;
        c += (ulong)x[3] + y[3];
        z[3] = (uint)c;
        c >>= 32;
        c += (ulong)x[4] + y[4];
        z[4] = (uint)c;
        c >>= 32;
        c += (ulong)x[5] + y[5];
        z[5] = (uint)c;
        c >>= 32;
        c += (ulong)x[6] + y[6];
        z[6] = (uint)c;
        c >>= 32;
        c += (ulong)x[7] + y[7];
        z[7] = (uint)c;
        c >>= 32;
        return (uint)c;
    }

    public static uint GetBit(ReadOnlySpan<uint> x, int bit)
    {
        if (bit == 0)
        {
            return x[0] & 1;
        }
        else if ((bit & 255) != bit)
        {
            return 0;
        }

        int w = bit >> 5;
        int b = bit & 31;
        return (x[w] >> b) & 1;
    }

    public static bool Gte(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y)
    {
        for (int i = 7; i >= 0; --i)
        {
            uint x_i = x[i], y_i = y[i];
            if (x_i < y_i)
            {
                return false;
            }

            if (x_i > y_i)
            {
                return true;
            }
        }

        return true;
    }

    public static bool IsOne(ReadOnlySpan<uint> x)
    {
        if (x[0] != 1)
        {
            return false;
        }

        for (int i = 1; i < 8; ++i)
        {
            if (x[i] != 0)
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsZero(ReadOnlySpan<uint> x)
    {
        for (int i = 0; i < 8; ++i)
        {
            if (x[i] != 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Computes <c>zz = x * y</c> (256 x 256 -> 512 bits). <paramref name="zz"/> must not overlap the inputs.
    /// </summary>
    /// <param name="x">The first operand, eight 32-bit words, least significant first.</param>
    /// <param name="y">The second operand, eight 32-bit words, least significant first.</param>
    /// <param name="zz">Receives the 512-bit product as sixteen 32-bit words.</param>
    public static void Mul(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> zz)
    {
        if (BitConverter.IsLittleEndian)
        {
            Mul64(x, y, zz);
        }
        else
        {
            MulSoft(x, y, zz);
        }
    }

    /// <summary>
    /// Computes <c>zz = x * x</c> (256 -> 512 bits). <paramref name="zz"/> must not overlap <paramref name="x"/>.
    /// </summary>
    /// <param name="x">The operand, eight 32-bit words, least significant first.</param>
    /// <param name="zz">Receives the 512-bit square as sixteen 32-bit words.</param>
    public static void Square(ReadOnlySpan<uint> x, Span<uint> zz)
    {
        if (BitConverter.IsLittleEndian)
        {
            Square64(x, zz);
        }
        else
        {
            SquareSoft(x, zz);
        }
    }

    /// <summary>
    /// Multiplication on four 64-bit limbs (product scanning by rows, carried in a <see cref="UInt128"/>).<br/>
    /// On x64 each partial product compiles to a single MULX plus ADD/ADC, replacing the 64 partial
    /// products of the 32-bit path with 16. Little-endian only: eight little-endian 32-bit words are
    /// reinterpreted in place as four little-endian 64-bit limbs.
    /// </summary>
    private static void Mul64(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> zz)
    {
        ReadOnlySpan<ulong> xd = MemoryMarshal.Cast<uint, ulong>(x);
        ReadOnlySpan<ulong> yd = MemoryMarshal.Cast<uint, ulong>(y);
        Span<ulong> zd = MemoryMarshal.Cast<uint, ulong>(zz);

        // Reading the highest index first lets the JIT elide the remaining bounds checks.
        ulong x3 = xd[3], x2 = xd[2], x1 = xd[1], x0 = xd[0];
        ulong y3 = yd[3], y2 = yd[2], y1 = yd[1], y0 = yd[0];

        // Row x0: no overflow is possible in any accumulation below;
        // product + carry + limb <= (2^64-1)^2 + 2*(2^64-1) = 2^128 - 1.
        UInt128 c = (UInt128)x0 * y0;
        ulong z0 = (ulong)c;
        c >>= 64;
        c += (UInt128)x0 * y1;
        ulong z1 = (ulong)c;
        c >>= 64;
        c += (UInt128)x0 * y2;
        ulong z2 = (ulong)c;
        c >>= 64;
        c += (UInt128)x0 * y3;
        ulong z3 = (ulong)c;
        ulong z4 = (ulong)(c >> 64);

        // Row x1.
        c = ((UInt128)x1 * y0) + z1;
        z1 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x1 * y1) + z2;
        z2 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x1 * y2) + z3;
        z3 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x1 * y3) + z4;
        z4 = (ulong)c;
        ulong z5 = (ulong)(c >> 64);

        // Row x2.
        c = ((UInt128)x2 * y0) + z2;
        z2 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x2 * y1) + z3;
        z3 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x2 * y2) + z4;
        z4 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x2 * y3) + z5;
        z5 = (ulong)c;
        ulong z6 = (ulong)(c >> 64);

        // Row x3.
        c = ((UInt128)x3 * y0) + z3;
        z3 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x3 * y1) + z4;
        z4 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x3 * y2) + z5;
        z5 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x3 * y3) + z6;
        z6 = (ulong)c;

        zd[7] = (ulong)(c >> 64);
        zd[0] = z0;
        zd[1] = z1;
        zd[2] = z2;
        zd[3] = z3;
        zd[4] = z4;
        zd[5] = z5;
        zd[6] = z6;
    }

    /// <summary>
    /// Squaring on four 64-bit limbs: the six off-diagonal products are computed once,
    /// doubled by a 1-bit shift across the accumulator, then the four diagonal squares are added.
    /// Ten MULX in total (on x64 each <see cref="UInt128"/> product is a single MULX plus ADD/ADC).<br/>
    /// Little-endian only: eight little-endian 32-bit words are reinterpreted in place as four
    /// little-endian 64-bit limbs.<br/>
    /// The curve classes repeat this body verbatim inside their fused square-and-reduce loops;
    /// helper extraction is deliberately avoided because address-taken <c>out</c> parameters defeat
    /// register promotion in RyuJIT (measured ~9% slower). Keep the copies in sync.
    /// </summary>
    private static void Square64(ReadOnlySpan<uint> x, Span<uint> zz)
    {
        ReadOnlySpan<ulong> xd = MemoryMarshal.Cast<uint, ulong>(x);
        Span<ulong> zd = MemoryMarshal.Cast<uint, ulong>(zz);

        // Reading the highest index first lets the JIT elide the remaining bounds checks.
        ulong x3 = xd[3], x2 = xd[2], x1 = xd[1], x0 = xd[0];

        // Off-diagonal products x_i * x_j (i < j).
        UInt128 c = (UInt128)x0 * x1;
        ulong z1 = (ulong)c;
        c >>= 64;
        c += (UInt128)x0 * x2;
        ulong z2 = (ulong)c;
        c >>= 64;
        c += (UInt128)x0 * x3;
        ulong z3 = (ulong)c;
        ulong z4 = (ulong)(c >> 64);

        c = ((UInt128)x1 * x2) + z3;
        z3 = (ulong)c;
        c >>= 64;
        c += ((UInt128)x1 * x3) + z4;
        z4 = (ulong)c;
        ulong z5 = (ulong)(c >> 64);

        c = ((UInt128)x2 * x3) + z5;
        z5 = (ulong)c;
        ulong z6 = (ulong)(c >> 64);

        // Double the off-diagonal part.
        ulong z7 = z6 >> 63;
        z6 = (z6 << 1) | (z5 >> 63);
        z5 = (z5 << 1) | (z4 >> 63);
        z4 = (z4 << 1) | (z3 >> 63);
        z3 = (z3 << 1) | (z2 >> 63);
        z2 = (z2 << 1) | (z1 >> 63);
        z1 <<= 1;

        // Add the diagonal squares x_i^2.
        c = (UInt128)x0 * x0;
        ulong z0 = (ulong)c;
        c = (c >> 64) + z1;
        z1 = (ulong)c;
        c = ((UInt128)x1 * x1) + (ulong)(c >> 64) + z2;
        z2 = (ulong)c;
        c = (c >> 64) + z3;
        z3 = (ulong)c;
        c = ((UInt128)x2 * x2) + (ulong)(c >> 64) + z4;
        z4 = (ulong)c;
        c = (c >> 64) + z5;
        z5 = (ulong)c;
        c = ((UInt128)x3 * x3) + (ulong)(c >> 64) + z6;
        z6 = (ulong)c;
        z7 += (ulong)(c >> 64); // Cannot wrap: x^2 < 2^512, so the true top limb fits in 64 bits.

        zd[7] = z7;
        zd[0] = z0;
        zd[1] = z1;
        zd[2] = z2;
        zd[3] = z3;
        zd[4] = z4;
        zd[5] = z5;
        zd[6] = z6;
    }

    /// <summary>
    /// Portable 32-bit word implementation of <see cref="Mul"/>, used on big-endian platforms.
    /// </summary>
    /// <param name="x">The first operand, eight 32-bit words, least significant first.</param>
    /// <param name="y">The second operand, eight 32-bit words, least significant first.</param>
    /// <param name="zz">Receives the 512-bit product as sixteen 32-bit words.</param>
    internal static void MulSoft(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> zz)
    {
        ulong y_0 = y[0];
        ulong y_1 = y[1];
        ulong y_2 = y[2];
        ulong y_3 = y[3];
        ulong y_4 = y[4];
        ulong y_5 = y[5];
        ulong y_6 = y[6];
        ulong y_7 = y[7];
        {
            ulong c = 0, x_0 = x[0];
            c += x_0 * y_0;
            zz[0] = (uint)c;
            c >>= 32;
            c += x_0 * y_1;
            zz[1] = (uint)c;
            c >>= 32;
            c += x_0 * y_2;
            zz[2] = (uint)c;
            c >>= 32;
            c += x_0 * y_3;
            zz[3] = (uint)c;
            c >>= 32;
            c += x_0 * y_4;
            zz[4] = (uint)c;
            c >>= 32;
            c += x_0 * y_5;
            zz[5] = (uint)c;
            c >>= 32;
            c += x_0 * y_6;
            zz[6] = (uint)c;
            c >>= 32;
            c += x_0 * y_7;
            zz[7] = (uint)c;
            c >>= 32;
            zz[8] = (uint)c;
        }

        for (int i = 1; i < 8; ++i)
        {
            ulong c = 0, x_i = x[i];
            c += (x_i * y_0) + zz[i + 0];
            zz[i + 0] = (uint)c;
            c >>= 32;
            c += (x_i * y_1) + zz[i + 1];
            zz[i + 1] = (uint)c;
            c >>= 32;
            c += (x_i * y_2) + zz[i + 2];
            zz[i + 2] = (uint)c;
            c >>= 32;
            c += (x_i * y_3) + zz[i + 3];
            zz[i + 3] = (uint)c;
            c >>= 32;
            c += (x_i * y_4) + zz[i + 4];
            zz[i + 4] = (uint)c;
            c >>= 32;
            c += (x_i * y_5) + zz[i + 5];
            zz[i + 5] = (uint)c;
            c >>= 32;
            c += (x_i * y_6) + zz[i + 6];
            zz[i + 6] = (uint)c;
            c >>= 32;
            c += (x_i * y_7) + zz[i + 7];
            zz[i + 7] = (uint)c;
            c >>= 32;
            zz[i + 8] = (uint)c;
        }
    }

    /// <summary>
    /// Portable 32-bit word implementation of <see cref="Square"/>, used on big-endian platforms.
    /// </summary>
    /// <param name="x">The operand, eight 32-bit words, least significant first.</param>
    /// <param name="zz">Receives the 512-bit square as sixteen 32-bit words.</param>
    internal static void SquareSoft(ReadOnlySpan<uint> x, Span<uint> zz)
    {
        ulong x_0 = x[0];
        ulong zz_1;

        uint c = 0, w;
        {
            int i = 7, j = 16;
            do
            {
                ulong xVal = x[i--];
                ulong p = xVal * xVal;
                zz[--j] = (c << 31) | (uint)(p >> 33);
                zz[--j] = (uint)(p >> 1);
                c = (uint)p;
            }
            while (i > 0);
            {
                ulong p = x_0 * x_0;
                zz_1 = (ulong)(c << 31) | (p >> 33);
                zz[0] = (uint)p;
                c = (uint)(p >> 32) & 1;
            }
        }

        ulong x_1 = x[1];
        ulong zz_2 = zz[2];
        {
            zz_1 += x_1 * x_0;
            w = (uint)zz_1;
            zz[1] = (w << 1) | c;
            c = w >> 31;
            zz_2 += zz_1 >> 32;
        }

        ulong x_2 = x[2];
        ulong zz_3 = zz[3];
        ulong zz_4 = zz[4];
        {
            zz_2 += x_2 * x_0;
            w = (uint)zz_2;
            zz[2] = (w << 1) | c;
            c = w >> 31;
            zz_3 += (zz_2 >> 32) + (x_2 * x_1);
            zz_4 += zz_3 >> 32;
            zz_3 &= M;
        }

        ulong x_3 = x[3];
        ulong zz_5 = zz[5] + (zz_4 >> 32);
        zz_4 &= M;
        ulong zz_6 = zz[6] + (zz_5 >> 32);
        zz_5 &= M;
        {
            zz_3 += x_3 * x_0;
            w = (uint)zz_3;
            zz[3] = (w << 1) | c;
            c = w >> 31;
            zz_4 += (zz_3 >> 32) + (x_3 * x_1);
            zz_5 += (zz_4 >> 32) + (x_3 * x_2);
            zz_4 &= M;
            zz_6 += zz_5 >> 32;
            zz_5 &= M;
        }

        ulong x_4 = x[4];
        ulong zz_7 = zz[7] + (zz_6 >> 32);
        zz_6 &= M;
        ulong zz_8 = zz[8] + (zz_7 >> 32);
        zz_7 &= M;
        {
            zz_4 += x_4 * x_0;
            w = (uint)zz_4;
            zz[4] = (w << 1) | c;
            c = w >> 31;
            zz_5 += (zz_4 >> 32) + (x_4 * x_1);
            zz_6 += (zz_5 >> 32) + (x_4 * x_2);
            zz_5 &= M;
            zz_7 += (zz_6 >> 32) + (x_4 * x_3);
            zz_6 &= M;
            zz_8 += zz_7 >> 32;
            zz_7 &= M;
        }

        ulong x_5 = x[5];
        ulong zz_9 = zz[9] + (zz_8 >> 32);
        zz_8 &= M;
        ulong zz_10 = zz[10] + (zz_9 >> 32);
        zz_9 &= M;
        {
            zz_5 += x_5 * x_0;
            w = (uint)zz_5;
            zz[5] = (w << 1) | c;
            c = w >> 31;
            zz_6 += (zz_5 >> 32) + (x_5 * x_1);
            zz_7 += (zz_6 >> 32) + (x_5 * x_2);
            zz_6 &= M;
            zz_8 += (zz_7 >> 32) + (x_5 * x_3);
            zz_7 &= M;
            zz_9 += (zz_8 >> 32) + (x_5 * x_4);
            zz_8 &= M;
            zz_10 += zz_9 >> 32;
            zz_9 &= M;
        }

        ulong x_6 = x[6];
        ulong zz_11 = zz[11] + (zz_10 >> 32);
        zz_10 &= M;
        ulong zz_12 = zz[12] + (zz_11 >> 32);
        zz_11 &= M;
        {
            zz_6 += x_6 * x_0;
            w = (uint)zz_6;
            zz[6] = (w << 1) | c;
            c = w >> 31;
            zz_7 += (zz_6 >> 32) + (x_6 * x_1);
            zz_8 += (zz_7 >> 32) + (x_6 * x_2);
            zz_7 &= M;
            zz_9 += (zz_8 >> 32) + (x_6 * x_3);
            zz_8 &= M;
            zz_10 += (zz_9 >> 32) + (x_6 * x_4);
            zz_9 &= M;
            zz_11 += (zz_10 >> 32) + (x_6 * x_5);
            zz_10 &= M;
            zz_12 += zz_11 >> 32;
            zz_11 &= M;
        }

        ulong x_7 = x[7];
        ulong zz_13 = zz[13] + (zz_12 >> 32);
        zz_12 &= M;
        ulong zz_14 = zz[14] + (zz_13 >> 32);
        zz_13 &= M;
        {
            zz_7 += x_7 * x_0;
            w = (uint)zz_7;
            zz[7] = (w << 1) | c;
            c = w >> 31;
            zz_8 += (zz_7 >> 32) + (x_7 * x_1);
            zz_9 += (zz_8 >> 32) + (x_7 * x_2);
            zz_10 += (zz_9 >> 32) + (x_7 * x_3);
            zz_11 += (zz_10 >> 32) + (x_7 * x_4);
            zz_12 += (zz_11 >> 32) + (x_7 * x_5);
            zz_13 += (zz_12 >> 32) + (x_7 * x_6);
            zz_14 += zz_13 >> 32;
        }

        w = (uint)zz_8;
        zz[8] = (w << 1) | c;
        c = w >> 31;
        w = (uint)zz_9;
        zz[9] = (w << 1) | c;
        c = w >> 31;
        w = (uint)zz_10;
        zz[10] = (w << 1) | c;
        c = w >> 31;
        w = (uint)zz_11;
        zz[11] = (w << 1) | c;
        c = w >> 31;
        w = (uint)zz_12;
        zz[12] = (w << 1) | c;
        c = w >> 31;
        w = (uint)zz_13;
        zz[13] = (w << 1) | c;
        c = w >> 31;
        w = (uint)zz_14;
        zz[14] = (w << 1) | c;
        c = w >> 31;
        w = zz[15] + (uint)(zz_14 >> 32);
        zz[15] = (w << 1) | c;
    }

    public static int Sub(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
    {
        long c = 0;
        c += (long)x[0] - y[0];
        z[0] = (uint)c;
        c >>= 32;
        c += (long)x[1] - y[1];
        z[1] = (uint)c;
        c >>= 32;
        c += (long)x[2] - y[2];
        z[2] = (uint)c;
        c >>= 32;
        c += (long)x[3] - y[3];
        z[3] = (uint)c;
        c >>= 32;
        c += (long)x[4] - y[4];
        z[4] = (uint)c;
        c >>= 32;
        c += (long)x[5] - y[5];
        z[5] = (uint)c;
        c >>= 32;
        c += (long)x[6] - y[6];
        z[6] = (uint)c;
        c >>= 32;
        c += (long)x[7] - y[7];
        z[7] = (uint)c;
        c >>= 32;
        return (int)c;
    }

    public static ulong Mul33Add(uint w, ReadOnlySpan<uint> x, int xOff, ReadOnlySpan<uint> y, int yOff, Span<uint> z, int zOff)
    {
        Debug.Assert(w >> 31 == 0);

        ulong c = 0, wVal = w;
        ulong x0 = x[xOff + 0];
        c += (wVal * x0) + y[yOff + 0];
        z[zOff + 0] = (uint)c;
        c >>= 32;
        ulong x1 = x[xOff + 1];
        c += (wVal * x1) + x0 + y[yOff + 1];
        z[zOff + 1] = (uint)c;
        c >>= 32;
        ulong x2 = x[xOff + 2];
        c += (wVal * x2) + x1 + y[yOff + 2];
        z[zOff + 2] = (uint)c;
        c >>= 32;
        ulong x3 = x[xOff + 3];
        c += (wVal * x3) + x2 + y[yOff + 3];
        z[zOff + 3] = (uint)c;
        c >>= 32;
        ulong x4 = x[xOff + 4];
        c += (wVal * x4) + x3 + y[yOff + 4];
        z[zOff + 4] = (uint)c;
        c >>= 32;
        ulong x5 = x[xOff + 5];
        c += (wVal * x5) + x4 + y[yOff + 5];
        z[zOff + 5] = (uint)c;
        c >>= 32;
        ulong x6 = x[xOff + 6];
        c += (wVal * x6) + x5 + y[yOff + 6];
        z[zOff + 6] = (uint)c;
        c >>= 32;
        ulong x7 = x[xOff + 7];
        c += (wVal * x7) + x6 + y[yOff + 7];
        z[zOff + 7] = (uint)c;
        c >>= 32;
        c += x7;
        return c;
    }

    public static uint Mul33DWordAdd(uint x, ulong y, Span<uint> z, int zOff)
    {
        Debug.Assert(x >> 31 == 0);
        Debug.Assert(zOff <= 4);
        ulong c = 0, xVal = x;
        ulong y00 = y & M;
        c += (xVal * y00) + z[zOff + 0];
        z[zOff + 0] = (uint)c;
        c >>= 32;
        ulong y01 = y >> 32;
        c += (xVal * y01) + y00 + z[zOff + 1];
        z[zOff + 1] = (uint)c;
        c >>= 32;
        c += y01 + z[zOff + 2];
        z[zOff + 2] = (uint)c;
        c >>= 32;
        c += z[zOff + 3];
        z[zOff + 3] = (uint)c;
        c >>= 32;
        return c == 0 ? 0 : Nat.IncAt(8, z, zOff, 4);
    }
}
