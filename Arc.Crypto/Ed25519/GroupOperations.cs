// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Arc.Crypto.Ed25519;

#pragma warning disable SA1300 // Element should begin with upper-case letter
#pragma warning disable SA1312 // Variable names should begin with lower-case letter

internal static class GroupOperations
{
    public static void ge_scalarmult_base(out GroupElementP3 h, Span<byte> a)
    {
        Span<sbyte> e = stackalloc sbyte[64];
        sbyte carry;
        GroupElementP1P1 r;
        GroupElementP2 s;
        GroupElementPreComp t;
        int i;

        for (i = 0; i < 32; ++i)
        {
            e[(2 * i) + 0] = (sbyte)((a[i] >> 0) & 15);
            e[(2 * i) + 1] = (sbyte)((a[i] >> 4) & 15);
        }

        carry = 0;
        for (i = 0; i < 63; ++i)
        {
            e[i] += carry;
            carry = (sbyte)(e[i] + 8);
            carry >>= 4;
            e[i] -= (sbyte)(carry << 4);
        }

        e[63] += carry;

        ge_p3_0(out h);
        for (i = 1; i < 64; i += 2)
        {
            select(out t, i / 2, e[i]);
            ge_madd(out r, ref h, ref t);
            ge_p1p1_to_p3(out h, ref r);
        }

        ge_p3_dbl(out r, ref h);
        ge_p1p1_to_p2(out s, ref r);
        ge_p2_dbl(out r, ref s);
        ge_p1p1_to_p2(out s, ref r);
        ge_p2_dbl(out r, ref s);
        ge_p1p1_to_p2(out s, ref r);
        ge_p2_dbl(out r, ref s);
        ge_p1p1_to_p3(out h, ref r);

        for (i = 0; i < 64; i += 2)
        {
            select(out t, i / 2, e[i]);
            ge_madd(out r, ref h, ref t);
            ge_p1p1_to_p3(out h, ref r);
        }
    }

    public static void ge_p3_tobytes(Span<byte> s, ref GroupElementP3 h)
    {
        FieldElement recip;
        FieldElement x;
        FieldElement y;

        FieldOperations.fe_invert(out recip, ref h.Z);
        FieldOperations.fe_mul(out x, ref h.X, ref recip);
        FieldOperations.fe_mul(out y, ref h.Y, ref recip);
        FieldOperations.fe_tobytes(s, ref y);
        s[31] ^= (byte)(FieldOperations.fe_isnegative(ref x) << 7);
    }

    public static void ge_p1p1_to_p3(out GroupElementP3 r, ref GroupElementP1P1 p)
    {
        FieldOperations.fe_mul(out r.X, ref p.X, ref p.T);
        FieldOperations.fe_mul(out r.Y, ref p.Y, ref p.Z);
        FieldOperations.fe_mul(out r.Z, ref p.Z, ref p.T);
        FieldOperations.fe_mul(out r.T, ref p.X, ref p.Y);
    }

    public static void ge_p1p1_to_p2(out GroupElementP2 r, ref GroupElementP1P1 p)
    {
        FieldOperations.fe_mul(out r.X, ref p.X, ref p.T);
        FieldOperations.fe_mul(out r.Y, ref p.Y, ref p.Z);
        FieldOperations.fe_mul(out r.Z, ref p.Z, ref p.T);
    }

    public static void ge_p3_0(out GroupElementP3 h)
    {
        FieldOperations.fe_0(out h.X);
        FieldOperations.fe_1(out h.Y);
        FieldOperations.fe_1(out h.Z);
        FieldOperations.fe_0(out h.T);
    }

    public static void ge_p3_dbl(out GroupElementP1P1 r, ref GroupElementP3 p)
    {
        var q = new GroupElementP2(ref p);
        ge_p2_dbl(out r, ref q);
    }

    public static void ge_p2_dbl(out GroupElementP1P1 r, ref GroupElementP2 p)
    {
        FieldElement t0;

        FieldOperations.fe_sq(out r.X, ref p.X);
        FieldOperations.fe_sq(out r.Z, ref p.Y);
        FieldOperations.fe_sq2(out r.T, ref p.Z);
        FieldOperations.fe_add(out r.Y, ref p.X, ref p.Y);
        FieldOperations.fe_sq(out t0, ref r.Y);
        FieldOperations.fe_add(out r.Y, ref r.Z, ref r.X);
        FieldOperations.fe_sub(out r.Z, ref r.Z, ref r.X);
        FieldOperations.fe_sub(out r.X, ref t0, ref r.Y);
        FieldOperations.fe_sub(out r.T, ref r.T, ref r.Z);
    }

    public static byte equal(byte b, byte c)
    {
        byte ub = b;
        byte uc = c;
        byte x = (byte)(ub ^ uc);
        uint y = x;
        unchecked
        {
            y -= 1;
        }

        y >>= 31;
        return (byte)y;
    }

    public static byte negative(sbyte b)
    {
        ulong x = unchecked((ulong)(long)b);
        x >>= 63;
        return (byte)x;
    }

    public static void cmov(ref GroupElementPreComp t, ref GroupElementPreComp u, byte b)
    {
        FieldOperations.fe_cmov(ref t.yplusx, ref u.yplusx, b);
        FieldOperations.fe_cmov(ref t.yminusx, ref u.yminusx, b);
        FieldOperations.fe_cmov(ref t.xy2d, ref u.xy2d, b);
    }

    public static void select(out GroupElementPreComp t, int pos, sbyte b)
    {
        GroupElementPreComp minust;
        byte bnegative = negative(b);
        byte babs = (byte)(b - (((-bnegative) & b) << 1));

        ge_precomp_0(out t);
        var table = LookupTables.Base[pos];
        cmov(ref t, ref table[0], equal(babs, 1));
        cmov(ref t, ref table[1], equal(babs, 2));
        cmov(ref t, ref table[2], equal(babs, 3));
        cmov(ref t, ref table[3], equal(babs, 4));
        cmov(ref t, ref table[4], equal(babs, 5));
        cmov(ref t, ref table[5], equal(babs, 6));
        cmov(ref t, ref table[6], equal(babs, 7));
        cmov(ref t, ref table[7], equal(babs, 8));
        minust.yplusx = t.yminusx;
        minust.yminusx = t.yplusx;
        FieldOperations.fe_neg(out minust.xy2d, ref t.xy2d);
        cmov(ref t, ref minust, bnegative);
    }

    public static void ge_madd(out GroupElementP1P1 r, ref GroupElementP3 p, ref GroupElementPreComp q)
    {
        FieldElement t0;
        FieldOperations.fe_add(out r.X, ref p.Y, ref p.X);
        FieldOperations.fe_sub(out r.Y, ref p.Y, ref p.X);
        FieldOperations.fe_mul(out r.Z, ref r.X, ref q.yplusx);
        FieldOperations.fe_mul(out r.Y, ref r.Y, ref q.yminusx);
        FieldOperations.fe_mul(out r.T, ref q.xy2d, ref p.T);
        FieldOperations.fe_add(out t0, ref p.Z, ref p.Z);
        FieldOperations.fe_sub(out r.X, ref r.Z, ref r.Y);
        FieldOperations.fe_add(out r.Y, ref r.Z, ref r.Y);
        FieldOperations.fe_add(out r.Z, ref t0, ref r.T);
        FieldOperations.fe_sub(out r.T, ref t0, ref r.T);
    }

    public static void ge_precomp_0(out GroupElementPreComp h)
    {
        FieldOperations.fe_1(out h.yplusx);
        FieldOperations.fe_1(out h.yminusx);
        FieldOperations.fe_0(out h.xy2d);
    }

    public static int ge_frombytes_negate_vartime(out GroupElementP3 h, byte[] data)
    {
        FieldElement u;
        FieldElement v;
        FieldElement v3;
        FieldElement vxx;
        FieldElement check;

        FieldOperations.fe_frombytes(out h.Y, data, offset);
        FieldOperations.fe_1(out h.Z);
        FieldOperations.fe_sq(out u, ref h.Y);
        FieldOperations.fe_mul(out v, ref u, ref LookupTables.d);
        FieldOperations.fe_sub(out u, ref u, ref h.Z);       /* u = y^2-1 */
        FieldOperations.fe_add(out v, ref v, ref h.Z);       /* v = dy^2+1 */

        FieldOperations.fe_sq(out v3, ref v);
        FieldOperations.fe_mul(out v3, ref v3, ref v);        /* v3 = v^3 */
        FieldOperations.fe_sq(out h.X, ref v3);
        FieldOperations.fe_mul(out h.X, ref h.X, ref v);
        FieldOperations.fe_mul(out h.X, ref h.X, ref u);    /* x = uv^7 */

        FieldOperations.fe_pow22523(out h.X, ref h.X); /* x = (uv^7)^((q-5)/8) */
        FieldOperations.fe_mul(out h.X, ref h.X, ref v3);
        FieldOperations.fe_mul(out h.X, ref h.X, ref u);    /* x = uv^3(uv^7)^((q-5)/8) */

        FieldOperations.fe_sq(out vxx, ref h.X);
        FieldOperations.fe_mul(out vxx, ref vxx, ref v);
        FieldOperations.fe_sub(out check, ref vxx, ref u);    /* vx^2-u */
        if (FieldOperations.fe_isnonzero(ref check) != 0)
        {
            FieldOperations.fe_add(out check, ref vxx, ref u);  /* vx^2+u */
            if (FieldOperations.fe_isnonzero(ref check) != 0)
            {
                h = default(GroupElementP3);
                return -1;
            }

            FieldOperations.fe_mul(out h.X, ref h.X, ref LookupTables.sqrtm1);
        }

        if (FieldOperations.fe_isnegative(ref h.X) == (data[31] >> 7))
        {
            FieldOperations.fe_neg(out h.X, ref h.X);
        }

        FieldOperations.fe_mul(out h.T, ref h.X, ref h.Y);
        return 0;
    }
}
