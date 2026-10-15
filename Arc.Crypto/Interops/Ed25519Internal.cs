// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Buffers.Binary;

#pragma warning disable SA1310 // Field names should not contain underscore
#pragma warning disable SA1307 // Accessible fields should begin with upper-case letter

namespace Arc.Crypto.Ed25519;

/// <summary>
/// Field arithmetic modulo <c>p = 2^255 - 19</c> on <see cref="fe25519"/>, ported from libsodium (fe_51).<br/>
/// Used to convert between Ed25519 and X25519 public keys.
/// </summary>
internal static partial class Ed25519Internal
{
    private const ulong Mask = 0x7ffffffffffffUL;

    /// <summary>
    /// Loads a field element from 32 little-endian bytes.<br/>
    /// Bit 255 is ignored, and values in <c>[p, 2^255)</c> are accepted without reduction.
    /// </summary>
    /// <param name="h">Receives the field element.</param>
    /// <param name="s">The 32-byte encoding.</param>
    public static void fe25519_frombytes(out fe25519 h, ReadOnlySpan<byte> s)
    {// checked
        ulong h0, h1, h2, h3, h4;

        h0 = BinaryPrimitives.ReadUInt64LittleEndian(s) & Mask;
        h1 = (BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(6)) >> 3) & Mask;
        h2 = (BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(12)) >> 6) & Mask;
        h3 = (BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(19)) >> 1) & Mask;
        h4 = (BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(24)) >> 12) & Mask;

        h.h0 = h0;
        h.h1 = h1;
        h.h2 = h2;
        h.h3 = h3;
        h.h4 = h4;
    }

    /// <summary>
    /// Writes the canonical (fully reduced) 32-byte little-endian encoding of a field element.
    /// </summary>
    /// <param name="s">The span that receives the encoding; at least 32 bytes.</param>
    /// <param name="h">The field element.</param>
    public static void fe25519_tobytes(Span<byte> s, ref fe25519 h)
    {// checked
        fe25519 t;
        ulong t0, t1, t2, t3;

        fe25519_reduce(out t, ref h);
        t0 = t.h0 | (t.h1 << 51);
        t1 = (t.h1 >> 13) | (t.h2 << 38);
        t2 = (t.h2 >> 26) | (t.h3 << 25);
        t3 = (t.h3 >> 39) | (t.h4 << 12);
        BinaryPrimitives.WriteUInt64LittleEndian(s, t0);
        BinaryPrimitives.WriteUInt64LittleEndian(s.Slice(8), t1);
        BinaryPrimitives.WriteUInt64LittleEndian(s.Slice(16), t2);
        BinaryPrimitives.WriteUInt64LittleEndian(s.Slice(24), t3);
    }

    /// <summary>
    /// Reduces a field element to its canonical form: the value is below <c>p</c> and every limb is below 2^51.
    /// </summary>
    /// <param name="h">Receives the reduced field element.</param>
    /// <param name="f">The field element to reduce.</param>
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

    /// <summary>
    /// Computes <c>h = f + g</c> limb by limb, without carry propagation.
    /// </summary>
    /// <param name="h">Receives the sum.</param>
    /// <param name="f">The first operand.</param>
    /// <param name="g">The second operand.</param>
    public static void fe25519_add(out fe25519 h, ref fe25519 f, ref fe25519 g)
    {// checked
        h = new(f.h0 + g.h0, f.h1 + g.h1, f.h2 + g.h2, f.h3 + g.h3, f.h4 + g.h4);
    }

    /// <summary>
    /// Computes <c>h = f - g</c> (as <c>f + 2p - g</c>); <paramref name="g"/> is carried first so that every limb stays non-negative.
    /// </summary>
    /// <param name="h">Receives the difference.</param>
    /// <param name="f">The minuend.</param>
    /// <param name="g">The subtrahend.</param>
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

    /// <summary>
    /// Computes <c>h = f^2</c>.
    /// </summary>
    /// <param name="h">Receives the square.</param>
    /// <param name="f">The operand.</param>
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

    /// <summary>
    /// Computes <c>h = f * g</c>.<br/>
    /// Each 128-bit column sum is kept as a (hi, lo) pair of <see cref="ulong"/> built with <see cref="Math.BigMul(ulong, ulong, out ulong)"/>;
    /// <see cref="UInt128"/> operators are avoided because the JIT stops inlining them in a method this large.
    /// </summary>
    /// <param name="h">Receives the product.</param>
    /// <param name="f">The first operand; every limb must be below 2^54 so that each column sum stays below 2^115 and every carry fits in 64 bits.</param>
    /// <param name="g">The second operand; same limb bound as <paramref name="f"/>.</param>
    public static void fe25519_mul(out fe25519 h, ref fe25519 f, ref fe25519 g)
    {// checked
        // Every caller passes limbs below 2^53, so 19 * limb fits in 64 bits, each product is below 2^111
        // and each five-term column sum is below 2^114: the (hi, lo) pairs never overflow.
        ulong f0, f1, f2, f3, f4;
        ulong f1_19, f2_19, f3_19, f4_19;
        ulong g0, g1, g2, g3, g4;
        ulong lo0, lo1, lo2, lo3, lo4;
        ulong hi0, hi1, hi2, hi3, hi4;
        ulong l, hh;
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

        // r0 = f0 * g0 + f1_19 * g4 + f2_19 * g3 + f3_19 * g2 + f4_19 * g1
        hi0 = Math.BigMul(f0, g0, out lo0);
        hh = Math.BigMul(f1_19, g4, out l);
        lo0 += l;
        hi0 += hh + (lo0 < l ? 1UL : 0UL);
        hh = Math.BigMul(f2_19, g3, out l);
        lo0 += l;
        hi0 += hh + (lo0 < l ? 1UL : 0UL);
        hh = Math.BigMul(f3_19, g2, out l);
        lo0 += l;
        hi0 += hh + (lo0 < l ? 1UL : 0UL);
        hh = Math.BigMul(f4_19, g1, out l);
        lo0 += l;
        hi0 += hh + (lo0 < l ? 1UL : 0UL);

        // r1 = f0 * g1 + f1 * g0 + f2_19 * g4 + f3_19 * g3 + f4_19 * g2
        hi1 = Math.BigMul(f0, g1, out lo1);
        hh = Math.BigMul(f1, g0, out l);
        lo1 += l;
        hi1 += hh + (lo1 < l ? 1UL : 0UL);
        hh = Math.BigMul(f2_19, g4, out l);
        lo1 += l;
        hi1 += hh + (lo1 < l ? 1UL : 0UL);
        hh = Math.BigMul(f3_19, g3, out l);
        lo1 += l;
        hi1 += hh + (lo1 < l ? 1UL : 0UL);
        hh = Math.BigMul(f4_19, g2, out l);
        lo1 += l;
        hi1 += hh + (lo1 < l ? 1UL : 0UL);

        // r2 = f0 * g2 + f1 * g1 + f2 * g0 + f3_19 * g4 + f4_19 * g3
        hi2 = Math.BigMul(f0, g2, out lo2);
        hh = Math.BigMul(f1, g1, out l);
        lo2 += l;
        hi2 += hh + (lo2 < l ? 1UL : 0UL);
        hh = Math.BigMul(f2, g0, out l);
        lo2 += l;
        hi2 += hh + (lo2 < l ? 1UL : 0UL);
        hh = Math.BigMul(f3_19, g4, out l);
        lo2 += l;
        hi2 += hh + (lo2 < l ? 1UL : 0UL);
        hh = Math.BigMul(f4_19, g3, out l);
        lo2 += l;
        hi2 += hh + (lo2 < l ? 1UL : 0UL);

        // r3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4_19 * g4
        hi3 = Math.BigMul(f0, g3, out lo3);
        hh = Math.BigMul(f1, g2, out l);
        lo3 += l;
        hi3 += hh + (lo3 < l ? 1UL : 0UL);
        hh = Math.BigMul(f2, g1, out l);
        lo3 += l;
        hi3 += hh + (lo3 < l ? 1UL : 0UL);
        hh = Math.BigMul(f3, g0, out l);
        lo3 += l;
        hi3 += hh + (lo3 < l ? 1UL : 0UL);
        hh = Math.BigMul(f4_19, g4, out l);
        lo3 += l;
        hi3 += hh + (lo3 < l ? 1UL : 0UL);

        // r4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0
        hi4 = Math.BigMul(f0, g4, out lo4);
        hh = Math.BigMul(f1, g3, out l);
        lo4 += l;
        hi4 += hh + (lo4 < l ? 1UL : 0UL);
        hh = Math.BigMul(f2, g2, out l);
        lo4 += l;
        hi4 += hh + (lo4 < l ? 1UL : 0UL);
        hh = Math.BigMul(f3, g1, out l);
        lo4 += l;
        hi4 += hh + (lo4 < l ? 1UL : 0UL);
        hh = Math.BigMul(f4, g0, out l);
        lo4 += l;
        hi4 += hh + (lo4 < l ? 1UL : 0UL);

        // carry = (ulong)(r >> 51), and r_next += carry on the (hi, lo) pairs.
        r00 = lo0 & Mask;
        carry = (lo0 >> 51) | (hi0 << 13);
        lo1 += carry;
        hi1 += lo1 < carry ? 1UL : 0UL;
        r01 = lo1 & Mask;
        carry = (lo1 >> 51) | (hi1 << 13);
        lo2 += carry;
        hi2 += lo2 < carry ? 1UL : 0UL;
        r02 = lo2 & Mask;
        carry = (lo2 >> 51) | (hi2 << 13);
        lo3 += carry;
        hi3 += lo3 < carry ? 1UL : 0UL;
        r03 = lo3 & Mask;
        carry = (lo3 >> 51) | (hi3 << 13);
        lo4 += carry;
        hi4 += lo4 < carry ? 1UL : 0UL;
        r04 = lo4 & Mask;
        carry = (lo4 >> 51) | (hi4 << 13);
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

    /// <summary>
    /// Computes <c>h = z^(p - 2)</c>, the inverse of <paramref name="z"/> (0 when <paramref name="z"/> is 0).
    /// </summary>
    /// <param name="h">Receives the inverse.</param>
    /// <param name="z">The field element to invert.</param>
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

/// <summary>
/// A field element modulo <c>2^255 - 19</c> in radix 2^51 (limb <c>h0</c> is least significant).<br/>
/// Limbs may exceed 51 bits between operations; <see cref="Ed25519Internal.fe25519_tobytes"/> reduces fully.
/// </summary>
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
