// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

#pragma warning disable SA1310 // Field names should not contain underscore
#pragma warning disable SA1307 // Accessible fields should begin with upper-case letter

namespace Benchmark.Obsolete.Ed25519;

internal static class Ed25519Helper
{
    private const ulong Mask = 0x7ffffffffffffUL;
    private const int Length = 32;

    private static fe25519 fe25519_sqrtm1 = new(
    1718705420411056, 234908883556509, 2233514472574048, 2117202627021982, 765476049583133);

    private static fe25519 ed25519_d = new(
   929955233495203, 466365720129213, 1662059464998953, 2033849074728123, 1442794654840575);

    private static fe25519 ed25519_d2 = new(
   1859910466990425, 932731440258426, 1072319116312658, 1815898335770999, 633789495995903);

    public static void fe25519_frombytes(out fe25519 h, ReadOnlySpan<byte> s)
    {// checked
        ulong h0, h1, h2, h3, h4;

        h0 = BitConverter.ToUInt64(s) & Mask;
        h1 = (BitConverter.ToUInt64(s.Slice(6)) >> 3) & Mask;
        h2 = (BitConverter.ToUInt64(s.Slice(12)) >> 6) & Mask;
        h3 = (BitConverter.ToUInt64(s.Slice(19)) >> 1) & Mask;
        h4 = (BitConverter.ToUInt64(s.Slice(24)) >> 12) & Mask;

        h.h0 = h0;
        h.h1 = h1;
        h.h2 = h2;
        h.h3 = h3;
        h.h4 = h4;
    }

    public static void fe25519_tobytes(Span<byte> s, ref fe25519 h)
    {// checked
        fe25519 t;
        ulong t0, t1, t2, t3;

        fe25519_reduce(out t, ref h);
        t0 = t.h0 | (t.h1 << 51);
        t1 = (t.h1 >> 13) | (t.h2 << 38);
        t2 = (t.h2 >> 26) | (t.h3 << 25);
        t3 = (t.h3 >> 39) | (t.h4 << 12);
        BitConverter.TryWriteBytes(s, t0);
        BitConverter.TryWriteBytes(s.Slice(8), t1);
        BitConverter.TryWriteBytes(s.Slice(16), t2);
        BitConverter.TryWriteBytes(s.Slice(24), t3);
    }

    public static void fe25519_reduce(out fe25519 h, ref fe25519 f)
    {// checked
        UInt128 t0, t1, t2, t3, t4;

        t0 = f.h0;
        t1 = f.h1;
        t2 = f.h2;
        t3 = f.h3;
        t4 = f.h4;

        t1 += t0 >> 51;
        t0 &= Mask;
        t2 += t1 >> 51;
        t1 &= Mask;
        t3 += t2 >> 51;
        t2 &= Mask;
        t4 += t3 >> 51;
        t3 &= Mask;
        t0 += 19 * (t4 >> 51);
        t4 &= Mask;

        t1 += t0 >> 51;
        t0 &= Mask;
        t2 += t1 >> 51;
        t1 &= Mask;
        t3 += t2 >> 51;
        t2 &= Mask;
        t4 += t3 >> 51;
        t3 &= Mask;
        t0 += 19 * (t4 >> 51);
        t4 &= Mask;

        t0 += 19UL;

        t1 += t0 >> 51;
        t0 &= Mask;
        t2 += t1 >> 51;
        t1 &= Mask;
        t3 += t2 >> 51;
        t2 &= Mask;
        t4 += t3 >> 51;
        t3 &= Mask;
        t0 += 19UL * (t4 >> 51);
        t4 &= Mask;

        t0 += 0x8000000000000 - 19UL;
        t1 += 0x8000000000000 - 1UL;
        t2 += 0x8000000000000 - 1UL;
        t3 += 0x8000000000000 - 1UL;
        t4 += 0x8000000000000 - 1UL;

        t1 += t0 >> 51;
        t0 &= Mask;
        t2 += t1 >> 51;
        t1 &= Mask;
        t3 += t2 >> 51;
        t2 &= Mask;
        t4 += t3 >> 51;
        t3 &= Mask;
        t4 &= Mask;

        h.h0 = (ulong)t0;
        h.h1 = (ulong)t1;
        h.h2 = (ulong)t2;
        h.h3 = (ulong)t3;
        h.h4 = (ulong)t4;
    }

    public static void fe25519_pow22523(out fe25519 h, ref fe25519 z)
    {// checked
        fe25519 t0, t1, t2;
        int i;

        fe25519_sq(out t0, ref z);
        fe25519_sq(out t1, ref t0);
        fe25519_sq(out t1, ref t1);
        fe25519_mul(out t1, ref z, ref t1);
        fe25519_mul(out t0, ref t0, ref t1);
        fe25519_sq(out t0, ref t0);
        fe25519_mul(out t0, ref t1, ref t0);
        fe25519_sq(out t1, ref t0);
        for (i = 1; i < 5; ++i)
        {
            fe25519_sq(out t1, ref t1);
        }

        fe25519_mul(out t0, ref t1, ref t0);
        fe25519_sq(out t1, ref t0);
        for (i = 1; i < 10; ++i)
        {
            fe25519_sq(out t1, ref t1);
        }

        fe25519_mul(out t1, ref t1, ref t0);
        fe25519_sq(out t2, ref t1);
        for (i = 1; i < 20; ++i)
        {
            fe25519_sq(out t2, ref t2);
        }

        fe25519_mul(out t1, ref t2, ref t1);
        for (i = 1; i < 11; ++i)
        {
            fe25519_sq(out t1, ref t1);
        }

        fe25519_mul(out t0, ref t1, ref t0);
        fe25519_sq(out t1, ref t0);
        for (i = 1; i < 50; ++i)
        {
            fe25519_sq(out t1, ref t1);
        }

        fe25519_mul(out t1, ref t1, ref t0);
        fe25519_sq(out t2, ref t1);
        for (i = 1; i < 100; ++i)
        {
            fe25519_sq(out t2, ref t2);
        }

        fe25519_mul(out t1, ref t2, ref t1);
        for (i = 1; i < 51; ++i)
        {
            fe25519_sq(out t1, ref t1);
        }

        fe25519_mul(out t0, ref t1, ref t0);
        fe25519_sq(out t0, ref t0);
        fe25519_sq(out t0, ref t0);
        fe25519_mul(out h, ref t0, ref z);
    }

    public static int ge25519_frombytes_negate_vartime(out ge25519_p3 h, ReadOnlySpan<byte> s)
    {
        fe25519 u;
        fe25519 v;
        fe25519 v3;
        fe25519 vxx;
        fe25519 m_root_check, p_root_check;

        fe25519_frombytes(out h.Y, s);
        h.Z = new(1);
        fe25519_sq(out u, ref h.Y);
        fe25519_mul(out v, ref u, ref ed25519_d);
        fe25519_sub(out u, ref u, ref h.Z); /* u = y^2-1 */
        fe25519_add(out v, ref v, ref h.Z); /* v = dy^2+1 */

        fe25519_sq(out v3, ref v);
        fe25519_mul(out v3, ref v3, ref v); /* v3 = v^3 */
        fe25519_sq(out h.X, ref v3);
        fe25519_mul(out h.X, ref h.X, ref v);
        fe25519_mul(out h.X, ref h.X, ref u); /* x = uv^7 */

        fe25519_pow22523(out h.X, ref h.X); /* x = (uv^7)^((q-5)/8) */
        fe25519_mul(out h.X, ref h.X, ref v3);
        fe25519_mul(out h.X, ref h.X, ref u); /* x = uv^3(uv^7)^((q-5)/8) */

        fe25519_sq(out vxx, ref h.X);
        fe25519_mul(out vxx, ref vxx, ref v);
        fe25519_sub(out m_root_check, ref vxx, ref u); /* vx^2-u */
        if (fe25519_iszero(ref m_root_check) == 0)
        {
            fe25519_add(out p_root_check, ref vxx, ref u); /* vx^2+u */
            if (fe25519_iszero(ref p_root_check) == 0)
            {
                h = default;
                return -1;
            }

            fe25519_mul(out h.X, ref h.X, ref fe25519_sqrtm1);
        }

        if (fe25519_isnegative(ref h.X) == (s[31] >> 7))
        {
            fe25519_neg(out h.X, ref h.X);
        }

        fe25519_mul(out h.T, ref h.X, ref h.Y);

        return 0;
    }

    public static int ge25519_has_small_order(ref ge25519_p3 p)
    {
        fe25519 recip;
        fe25519 x;
        fe25519 x_neg;
        fe25519 y;
        fe25519 y_sqrtm1;
        fe25519 c;
        int ret = 0;

        fe25519_invert(out recip, ref p.Z);
        fe25519_mul(out x, ref p.X, ref recip);
        ret |= fe25519_iszero(ref x);
        fe25519_mul(out y, ref p.Y, ref recip);
        ret |= fe25519_iszero(ref y);
        fe25519_neg(out x_neg, ref p.X);
        fe25519_mul(out y_sqrtm1, ref y, ref fe25519_sqrtm1);
        fe25519_sub(out c, ref y_sqrtm1, ref x);
        ret |= fe25519_iszero(ref c);
        fe25519_sub(out c, ref y_sqrtm1, ref x_neg);
        ret |= fe25519_iszero(ref c);

        return ret;
    }

    public static int ge25519_is_on_main_subgroup(ref ge25519_p3 p)
    {
        ge25519_p3 pl;
        ge25519_mul_l(out pl, ref p);
        return fe25519_iszero(ref pl.X);
    }

    public static void ge25519_mul_l(out ge25519_p3 r, ref ge25519_p3 p)
    {
        ge25519_p3 a10, a11, a100, a110, a1000, a1011, a10000, a100000, a100110,
            a1000000, a1010000, a1010011, a1100011, a1100111, a1101011, a10010011,
            a10010111, a10111101, a11010011, a11100111, a11101101, a11110101;

        ge25519_p3p3_dbl(out a10, ref p);
        ge25519_p3_add(out a11, ref p, ref a10);
        ge25519_p3_add(out a100, ref p, ref a11);
        ge25519_p3_add(out a110, ref a10, ref a100);
        ge25519_p3_add(out a1000, ref a10, ref a110);
        ge25519_p3_add(out a1011, ref a11, ref a1000);
        ge25519_p3p3_dbl(out a10000, ref a1000);
        ge25519_p3p3_dbl(out a100000, ref a10000);
        ge25519_p3_add(out a100110, ref a110, ref a100000);
        ge25519_p3p3_dbl(out a1000000, ref a100000);
        ge25519_p3_add(out a1010000, ref a10000, ref a1000000);
        ge25519_p3_add(out a1010011, ref a11, ref a1010000);
        ge25519_p3_add(out a1100011, ref a10000, ref a1010011);
        ge25519_p3_add(out a1100111, ref a100, ref a1100011);
        ge25519_p3_add(out a1101011, ref a100, ref a1100111);
        ge25519_p3_add(out a10010011, ref a1000000, ref a1010011);
        ge25519_p3_add(out a10010111, ref a100, ref a10010011);
        ge25519_p3_add(out a10111101, ref a100110, ref a10010111);
        ge25519_p3_add(out a11010011, ref a1000000, ref a10010011);
        ge25519_p3_add(out a11100111, ref a1010000, ref a10010111);
        ge25519_p3_add(out a11101101, ref a110, ref a11100111);
        ge25519_p3_add(out a11110101, ref a1000, ref a11101101);

        ge25519_p3_add(out r, ref a1011, ref a11110101);
        ge25519_p3_dbladd(ref r, 126, ref a1010011);
        ge25519_p3_dbladd(ref r, 9, ref a10);
        ge25519_p3_add(out r, ref r, ref a11110101);
        ge25519_p3_dbladd(ref r, 7, ref a1100111);
        ge25519_p3_dbladd(ref r, 9, ref a11110101);
        ge25519_p3_dbladd(ref r, 11, ref a10111101);
        ge25519_p3_dbladd(ref r, 8, ref a11100111);
        ge25519_p3_dbladd(ref r, 9, ref a1101011);
        ge25519_p3_dbladd(ref r, 6, ref a1011);
        ge25519_p3_dbladd(ref r, 14, ref a10010011);
        ge25519_p3_dbladd(ref r, 10, ref a1100011);
        ge25519_p3_dbladd(ref r, 9, ref a10010111);
        ge25519_p3_dbladd(ref r, 10, ref a11110101);
        ge25519_p3_dbladd(ref r, 8, ref a11010011);
        ge25519_p3_dbladd(ref r, 8, ref a11101101);
    }

    public static void ge25519_p3_add(out ge25519_p3 r, ref ge25519_p3 p, ref ge25519_p3 q)
    {
        ge25519_cached q_cached;
        ge25519_p1p1 p1p1;

        ge25519_p3_to_cached(out q_cached, ref q);
        ge25519_add_cached(out p1p1, ref p, ref q_cached);
        ge25519_p1p1_to_p3(out r, ref p1p1);
    }

    public static void ge25519_p3_dbladd(ref ge25519_p3 r, int n, ref ge25519_p3 q)
    {
        ge25519_p2 p2;
        ge25519_p1p1 p1p1 = default;
        int i;

        ge25519_p3_to_p2(out p2, ref r);
        for (i = 0; i < n; i++)
        {
            ge25519_p2_dbl(out p1p1, ref p2);
            ge25519_p1p1_to_p2(out p2, ref p1p1);
        }

        ge25519_p1p1_to_p3(out r, ref p1p1);
        ge25519_p3_add(out r, ref r, ref q);
    }

    public static void ge25519_p1p1_to_p2(out ge25519_p2 r, ref ge25519_p1p1 p)
    {
        fe25519_mul(out r.X, ref p.X, ref p.T);
        fe25519_mul(out r.Y, ref p.Y, ref p.Z);
        fe25519_mul(out r.Z, ref p.Z, ref p.T);
    }

    public static void ge25519_add_cached(out ge25519_p1p1 r, ref ge25519_p3 p, ref ge25519_cached q)
    {
        fe25519 t0;
        fe25519_add(out r.X, ref p.Y, ref p.X);
        fe25519_sub(out r.Y, ref p.Y, ref p.X);
        fe25519_mul(out r.Z, ref r.X, ref q.YplusX);
        fe25519_mul(out r.Y, ref r.Y, ref q.YminusX);
        fe25519_mul(out r.T, ref q.T2d, ref p.T);
        fe25519_mul(out r.X, ref p.Z, ref q.Z);
        fe25519_add(out t0, ref r.X, ref r.X);
        fe25519_sub(out r.X, ref r.Z, ref r.Y);
        fe25519_add(out r.Y, ref r.Z, ref r.Y);
        fe25519_add(out r.Z, ref t0, ref r.T);
        fe25519_sub(out r.T, ref t0, ref r.T);
    }

    public static void ge25519_p3_to_cached(out ge25519_cached r, ref ge25519_p3 p)
    {
        fe25519_add(out r.YplusX, ref p.Y, ref p.X);
        fe25519_sub(out r.YminusX, ref p.Y, ref p.X);
        r.Z = p.Z;
        fe25519_mul(out r.T2d, ref p.T, ref ed25519_d2);
    }

    public static void ge25519_p3p3_dbl(out ge25519_p3 r, ref ge25519_p3 p)
    {
        ge25519_p1p1 p1p1;
        ge25519_p3_dbl(out p1p1, ref p);
        ge25519_p1p1_to_p3(out r, ref p1p1);
    }

    public static void ge25519_p1p1_to_p3(out ge25519_p3 r, ref ge25519_p1p1 p)
    {
        fe25519_mul(out r.X, ref p.X, ref p.T);
        fe25519_mul(out r.Y, ref p.Y, ref p.Z);
        fe25519_mul(out r.Z, ref p.Z, ref p.T);
        fe25519_mul(out r.T, ref p.X, ref p.Y);
    }

    public static void ge25519_p3_dbl(out ge25519_p1p1 r, ref ge25519_p3 p)
    {
        ge25519_p2 q;
        ge25519_p3_to_p2(out q, ref p);
        ge25519_p2_dbl(out r, ref q);
    }

    public static void ge25519_p3_to_p2(out ge25519_p2 r, ref ge25519_p3 p)
    {
        r.X = p.X;
        r.Y = p.Y;
        r.Z = p.Z;
    }

    public static void ge25519_p2_dbl(out ge25519_p1p1 r, ref ge25519_p2 p)
    {
        fe25519 t0;

        fe25519_sq(out r.X, ref p.X);
        fe25519_sq(out r.Z, ref p.Y);
        fe25519_sq2(out r.T, ref p.Z);
        fe25519_add(out r.Y, ref p.X, ref p.Y);
        fe25519_sq(out t0, ref r.Y);
        fe25519_add(out r.Y, ref r.Z, ref r.X);
        fe25519_sub(out r.Z, ref r.Z, ref r.X);
        fe25519_sub(out r.X, ref t0, ref r.Y);
        fe25519_sub(out r.T, ref r.T, ref r.Z);
    }

    public static void fe25519_add(out fe25519 h, ref fe25519 f, ref fe25519 g)
    {// checked
        h = new(f.h0 + g.h0, f.h1 + g.h1, f.h2 + g.h2, f.h3 + g.h3, f.h4 + g.h4);
    }

    public static void fe25519_sub(out fe25519 h, ref fe25519 f, ref fe25519 g)
    {// checked
        ulong h0, h1, h2, h3, h4;

        h0 = g.h0;
        h1 = g.h1;
        h2 = g.h2;
        h3 = g.h3;
        h4 = g.h4;

        h1 += h0 >> 51;
        h0 &= Mask;
        h2 += h1 >> 51;
        h1 &= Mask;
        h3 += h2 >> 51;
        h2 &= Mask;
        h4 += h3 >> 51;
        h3 &= Mask;
        h0 += 19UL * (h4 >> 51);
        h4 &= Mask;

        h0 = (f.h0 + 0xfffffffffffdaUL) - h0;
        h1 = (f.h1 + 0xffffffffffffeUL) - h1;
        h2 = (f.h2 + 0xffffffffffffeUL) - h2;
        h3 = (f.h3 + 0xffffffffffffeUL) - h3;
        h4 = (f.h4 + 0xffffffffffffeUL) - h4;

        h = new fe25519(h0, h1, h2, h3, h4);
    }

    public static void fe25519_neg(out fe25519 h, ref fe25519 f)
    {// checked
        fe25519 zero = default;
        fe25519_sub(out h, ref zero, ref f);
    }

    public static int fe25519_isnegative(ref fe25519 f)
    {// checked
        Span<byte> span = stackalloc byte[Length];
        fe25519_tobytes(span, ref f);
        return span[0] & 1;
    }

    public static int is_zero(ReadOnlySpan<byte> n)
    {// checked
        byte d = 0;
        for (var i = 0; i < n.Length; i++)
        {
            d |= n[i];
        }

        return 1 & ((d - 1) >> 8);
    }

    public static int fe25519_iszero(ref fe25519 f)
    {// checked
        Span<byte> span = stackalloc byte[Length];
        fe25519_tobytes(span, ref f);
        return is_zero(span);
    }

    public static void fe25519_sq(out fe25519 h, ref fe25519 f)
    {// checked
        UInt128 r0, r1, r2, r3, r4;
        UInt128 f0, f1, f2, f3, f4;
        UInt128 f0_2, f1_2, f1_38, f2_38, f3_38, f3_19, f4_19;
        ulong r00, r01, r02, r03, r04;
        ulong carry;

        f0 = f.h0;
        f1 = f.h1;
        f2 = f.h2;
        f3 = f.h3;
        f4 = f.h4;

        f0_2 = f0 << 1;
        f1_2 = f1 << 1;

        f1_38 = 38UL * f1;
        f2_38 = 38UL * f2;
        f3_38 = 38UL * f3;

        f3_19 = 19UL * f3;
        f4_19 = 19UL * f4;

        r0 = (f0 * f0) + (f1_38 * f4) + (f2_38 * f3);
        r1 = (f0_2 * f1) + (f2_38 * f4) + (f3_19 * f3);
        r2 = (f0_2 * f2) + (f1 * f1) + (f3_38 * f4);
        r3 = (f0_2 * f3) + (f1_2 * f2) + (f4_19 * f4);
        r4 = (f0_2 * f4) + (f1_2 * f3) + (f2 * f2);

        r00 = ((ulong)r0) & Mask;
        carry = (ulong)(r0 >> 51);
        r1 += carry;
        r01 = ((ulong)r1) & Mask;
        carry = (ulong)(r1 >> 51);
        r2 += carry;
        r02 = ((ulong)r2) & Mask;
        carry = (ulong)(r2 >> 51);
        r3 += carry;
        r03 = ((ulong)r3) & Mask;
        carry = (ulong)(r3 >> 51);
        r4 += carry;
        r04 = ((ulong)r4) & Mask;
        carry = (ulong)(r4 >> 51);
        r00 += 19UL * carry;
        carry = r00 >> 51;
        r00 &= Mask;
        r01 += carry;
        carry = r01 >> 51;
        r01 &= Mask;
        r02 += carry;

        h.h0 = r00;
        h.h1 = r01;
        h.h2 = r02;
        h.h3 = r03;
        h.h4 = r04;
    }

    public static void fe25519_sq2(out fe25519 h, ref fe25519 f)
    {
        UInt128 r0, r1, r2, r3, r4;
        UInt128 f0, f1, f2, f3, f4;
        UInt128 f0_2, f1_2, f1_38, f2_38, f3_38, f3_19, f4_19;
        ulong r00, r01, r02, r03, r04;
        ulong carry;

        f0 = f.h0;
        f1 = f.h1;
        f2 = f.h2;
        f3 = f.h3;
        f4 = f.h4;

        f0_2 = f0 << 1;
        f1_2 = f1 << 1;

        f1_38 = 38UL * f1;
        f2_38 = 38UL * f2;
        f3_38 = 38UL * f3;

        f3_19 = 19UL * f3;
        f4_19 = 19UL * f4;

        r0 = (f0 * f0) + (f1_38 * f4) + (f2_38 * f3);
        r1 = (f0_2 * f1) + (f2_38 * f4) + (f3_19 * f3);
        r2 = (f0_2 * f2) + (f1 * f1) + (f3_38 * f4);
        r3 = (f0_2 * f3) + (f1_2 * f2) + (f4_19 * f4);
        r4 = (f0_2 * f4) + (f1_2 * f3) + (f2 * f2);

        r0 <<= 1;
        r1 <<= 1;
        r2 <<= 1;
        r3 <<= 1;
        r4 <<= 1;

        r00 = ((ulong)r0) & Mask;
        carry = (ulong)(r0 >> 51);
        r1 += carry;
        r01 = ((ulong)r1) & Mask;
        carry = (ulong)(r1 >> 51);
        r2 += carry;
        r02 = ((ulong)r2) & Mask;
        carry = (ulong)(r2 >> 51);
        r3 += carry;
        r03 = ((ulong)r3) & Mask;
        carry = (ulong)(r3 >> 51);
        r4 += carry;
        r04 = ((ulong)r4) & Mask;
        carry = (ulong)(r4 >> 51);
        r00 += 19UL * carry;
        carry = r00 >> 51;
        r00 &= Mask;
        r01 += carry;
        carry = r01 >> 51;
        r01 &= Mask;
        r02 += carry;

        h.h0 = r00;
        h.h1 = r01;
        h.h2 = r02;
        h.h3 = r03;
        h.h4 = r04;
    }

    public static void fe25519_mul(out fe25519 h, ref fe25519 f, ref fe25519 g)
    {// checked
        UInt128 r0, r1, r2, r3, r4;
        UInt128 f0, f1, f2, f3, f4;
        UInt128 f1_19, f2_19, f3_19, f4_19;
        UInt128 g0, g1, g2, g3, g4;
        ulong r00, r01, r02, r03, r04;
        ulong carry;

        f0 = f.h0;
        f1 = f.h1;
        f2 = f.h2;
        f3 = f.h3;
        f4 = f.h4;

        g0 = g.h0;
        g1 = g.h1;
        g2 = g.h2;
        g3 = g.h3;
        g4 = g.h4;

        f1_19 = 19UL * f1;
        f2_19 = 19UL * f2;
        f3_19 = 19UL * f3;
        f4_19 = 19UL * f4;

        r0 = (f0 * g0) + (f1_19 * g4) + (f2_19 * g3) + (f3_19 * g2) + (f4_19 * g1);
        r1 = (f0 * g1) + (f1 * g0) + (f2_19 * g4) + (f3_19 * g3) + (f4_19 * g2);
        r2 = (f0 * g2) + (f1 * g1) + (f2 * g0) + (f3_19 * g4) + (f4_19 * g3);
        r3 = (f0 * g3) + (f1 * g2) + (f2 * g1) + (f3 * g0) + (f4_19 * g4);
        r4 = (f0 * g4) + (f1 * g3) + (f2 * g2) + (f3 * g1) + (f4 * g0);

        r00 = ((ulong)r0) & Mask;
        carry = (ulong)(r0 >> 51);
        r1 += carry;
        r01 = ((ulong)r1) & Mask;
        carry = (ulong)(r1 >> 51);
        r2 += carry;
        r02 = ((ulong)r2) & Mask;
        carry = (ulong)(r2 >> 51);
        r3 += carry;
        r03 = ((ulong)r3) & Mask;
        carry = (ulong)(r3 >> 51);
        r4 += carry;
        r04 = ((ulong)r4) & Mask;
        carry = (ulong)(r4 >> 51);
        r00 += 19UL * carry;
        carry = r00 >> 51;
        r00 &= Mask;
        r01 += carry;
        carry = r01 >> 51;
        r01 &= Mask;
        r02 += carry;

        h.h0 = r00;
        h.h1 = r01;
        h.h2 = r02;
        h.h3 = r03;
        h.h4 = r04;
    }

    public static void fe25519_invert(out fe25519 h, ref fe25519 z)
    {// checked
        fe25519 t0, t1, t2, t3;
        int i;

        fe25519_sq(out t0, ref z);
        fe25519_sq(out t1, ref t0);
        fe25519_sq(out t1, ref t1);
        fe25519_mul(out t1, ref z, ref t1);
        fe25519_mul(out t0, ref t0, ref t1);
        fe25519_sq(out t2, ref t0);
        fe25519_mul(out t1, ref t1, ref t2);
        fe25519_sq(out t2, ref t1);
        for (i = 1; i < 5; ++i)
        {
            fe25519_sq(out t2, ref t2);
        }

        fe25519_mul(out t1, ref t2, ref t1);
        fe25519_sq(out t2, ref t1);
        for (i = 1; i < 10; ++i)
        {
            fe25519_sq(out t2, ref t2);
        }

        fe25519_mul(out t2, ref t2, ref t1);
        fe25519_sq(out t3, ref t2);
        for (i = 1; i < 20; ++i)
        {
            fe25519_sq(out t3, ref t3);
        }

        fe25519_mul(out t2, ref t3, ref t2);
        for (i = 1; i < 11; ++i)
        {
            fe25519_sq(out t2, ref t2);
        }

        fe25519_mul(out t1, ref t2, ref t1);
        fe25519_sq(out t2, ref t1);
        for (i = 1; i < 50; ++i)
        {
            fe25519_sq(out t2, ref t2);
        }

        fe25519_mul(out t2, ref t2, ref t1);
        fe25519_sq(out t3, ref t2);
        for (i = 1; i < 100; ++i)
        {
            fe25519_sq(out t3, ref t3);
        }

        fe25519_mul(out t2, ref t3, ref t2);
        for (i = 1; i < 51; ++i)
        {
            fe25519_sq(out t2, ref t2);
        }

        fe25519_mul(out t1, ref t2, ref t1);
        for (i = 1; i < 6; ++i)
        {
            fe25519_sq(out t1, ref t1);
        }

        fe25519_mul(out h, ref t1, ref t0);
    }
}

internal struct ge25519_p3
{
    public fe25519 X;
    public fe25519 Y;
    public fe25519 Z;
    public fe25519 T;
}

internal struct ge25519_p1p1
{
    public fe25519 X;
    public fe25519 Y;
    public fe25519 Z;
    public fe25519 T;
}

internal struct ge25519_p2
{
    public fe25519 X;
    public fe25519 Y;
    public fe25519 Z;
}

internal struct ge25519_cached
{
    public fe25519 YplusX;
    public fe25519 YminusX;
    public fe25519 Z;
    public fe25519 T2d;
}

internal struct fe25519
{
    public ulong h0;
    public ulong h1;
    public ulong h2;
    public ulong h3;
    public ulong h4;

    public fe25519(ulong h0)
    {
        this.h0 = h0;
    }

    public fe25519(ulong h0, ulong h1, ulong h2, ulong h3, ulong h4)
    {
        this.h0 = h0;
        this.h1 = h1;
        this.h2 = h2;
        this.h3 = h3;
        this.h4 = h4;
    }
}
