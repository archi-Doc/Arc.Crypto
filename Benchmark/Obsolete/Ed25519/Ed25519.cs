using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Benchmark.Obsolete.Ed25519;

internal static class fe
{
    public static void Add(out fe25519 h, ref fe25519 f, ref fe25519 g)
    {
        h = new(f.h0 + g.h0, f.h1 + g.h1, f.h2 + g.h2, f.h3 + g.h3, f.h4 + g.h4);
    }

    public static void Sub(out fe25519 h, ref fe25519 f, ref fe25519 g)
    {
        const ulong mask = 0x7ffffffffffffUL;
        ulong h0, h1, h2, h3, h4;

        h0 = g.h0;
        h1 = g.h1;
        h2 = g.h2;
        h3 = g.h3;
        h4 = g.h4;

        h1 += h0 >> 51;
        h0 &= mask;
        h2 += h1 >> 51;
        h1 &= mask;
        h3 += h2 >> 51;
        h2 &= mask;
        h4 += h3 >> 51;
        h3 &= mask;
        h0 += 19UL * (h4 >> 51);
        h4 &= mask;

        h0 = (f.h0 + 0xfffffffffffdaUL) - h0;
        h1 = (f.h1 + 0xffffffffffffeUL) - h1;
        h2 = (f.h2 + 0xffffffffffffeUL) - h2;
        h3 = (f.h3 + 0xffffffffffffeUL) - h3;
        h4 = (f.h4 + 0xffffffffffffeUL) - h4;

        h = new fe25519(h0, h1, h2, h3, h4);
    }

    public static void fe25519_sq(out fe25519 h, ref fe25519 f)
    {
        const ulong mask = 0x7ffffffffffffUL;
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

        r0 = f0 * f0 + f1_38 * f4 + f2_38 * f3;
        r1 = f0_2 * f1 + f2_38 * f4 + f3_19 * f3;
        r2 = f0_2 * f2 + f1 * f1 + f3_38 * f4;
        r3 = f0_2 * f3 + f1_2 * f2 + f4_19 * f4;
        r4 = f0_2 * f4 + f1_2 * f3 + f2 * f2;

        r00 = ((ulong)r0) & mask;
        carry = (ulong)(r0 >> 51);
        r1 += carry;
        r01 = ((ulong)r1) & mask;
        carry = (ulong)(r1 >> 51);
        r2 += carry;
        r02 = ((ulong)r2) & mask;
        carry = (ulong)(r2 >> 51);
        r3 += carry;
        r03 = ((ulong)r3) & mask;
        carry = (ulong)(r3 >> 51);
        r4 += carry;
        r04 = ((ulong)r4) & mask;
        carry = (ulong)(r4 >> 51);
        r00 += 19UL * carry;
        carry = r00 >> 51;
        r00 &= mask;
        r01 += carry;
        carry = r01 >> 51;
        r01 &= mask;
        r02 += carry;

        h.h0 = r00;
        h.h1 = r01;
        h.h2 = r02;
        h.h3 = r03;
        h.h4 = r04;
    }

    public static void fe25519_mul(out fe25519 h, ref fe25519 f, ref fe25519 g)
    {
        const ulong mask = 0x7ffffffffffffUL;
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

        r0 = f0 * g0 + f1_19 * g4 + f2_19 * g3 + f3_19 * g2 + f4_19 * g1;
        r1 = f0 * g1 + f1 * g0 + f2_19 * g4 + f3_19 * g3 + f4_19 * g2;
        r2 = f0 * g2 + f1 * g1 + f2 * g0 + f3_19 * g4 + f4_19 * g3;
        r3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4_19 * g4;
        r4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0;

        r00 = ((ulong)r0) & mask;
        carry = (ulong)(r0 >> 51);
        r1 += carry;
        r01 = ((ulong)r1) & mask;
        carry = (ulong)(r1 >> 51);
        r2 += carry;
        r02 = ((ulong)r2) & mask;
        carry = (ulong)(r2 >> 51);
        r3 += carry;
        r03 = ((ulong)r3) & mask;
        carry = (ulong)(r3 >> 51);
        r4 += carry;
        r04 = ((ulong)r4) & mask;
        carry = (ulong)(r4 >> 51);
        r00 += 19UL * carry;
        carry = r00 >> 51;
        r00 &= mask;
        r01 += carry;
        carry = r01 >> 51;
        r01 &= mask;
        r02 += carry;

        h.h0 = r00;
        h.h1 = r01;
        h.h2 = r02;
        h.h3 = r03;
        h.h4 = r04;
    }

    public static void Invert(out fe25519 h, ref fe25519 z)
    {
        fe25519 t0, t1, t2, t3;
        int i;

        h = default;
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
