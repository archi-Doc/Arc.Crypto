﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;

namespace Arc.Crypto.Ed25519;

#pragma warning disable SA1300 // Element should begin with upper-case letter
#pragma warning disable SA1312 // Variable names should begin with lower-case letter

internal static class FieldOperations
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void fe_0(out FieldElement h)
    {
        h = default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void fe_1(out FieldElement h)
    {
        h = new(1, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    public static void fe_cmov(ref FieldElement f, ref FieldElement g, int b)
    {
        var f0 = f.x0;
        var f1 = f.x1;
        var f2 = f.x2;
        var f3 = f.x3;
        var f4 = f.x4;
        var f5 = f.x5;
        var f6 = f.x6;
        var f7 = f.x7;
        var f8 = f.x8;
        var f9 = f.x9;
        var g0 = g.x0;
        var g1 = g.x1;
        var g2 = g.x2;
        var g3 = g.x3;
        var g4 = g.x4;
        var g5 = g.x5;
        var g6 = g.x6;
        var g7 = g.x7;
        var g8 = g.x8;
        var g9 = g.x9;
        var x0 = f0 ^ g0;
        var x1 = f1 ^ g1;
        var x2 = f2 ^ g2;
        var x3 = f3 ^ g3;
        var x4 = f4 ^ g4;
        var x5 = f5 ^ g5;
        var x6 = f6 ^ g6;
        var x7 = f7 ^ g7;
        var x8 = f8 ^ g8;
        var x9 = f9 ^ g9;
        b = -b;
        x0 &= b;
        x1 &= b;
        x2 &= b;
        x3 &= b;
        x4 &= b;
        x5 &= b;
        x6 &= b;
        x7 &= b;
        x8 &= b;
        x9 &= b;

        f = new(f0 ^ x0, f1 ^ x1, f2 ^ x2, f3 ^ x3, f4 ^ x4, f5 ^ x5, f6 ^ x6, f7 ^ x7, f8 ^ x8, f9 ^ x9);
    }

    public static void fe_add(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {
        var f0 = f.x0;
        var f1 = f.x1;
        var f2 = f.x2;
        var f3 = f.x3;
        var f4 = f.x4;
        var f5 = f.x5;
        var f6 = f.x6;
        var f7 = f.x7;
        var f8 = f.x8;
        var f9 = f.x9;
        var g0 = g.x0;
        var g1 = g.x1;
        var g2 = g.x2;
        var g3 = g.x3;
        var g4 = g.x4;
        var g5 = g.x5;
        var g6 = g.x6;
        var g7 = g.x7;
        var g8 = g.x8;
        var g9 = g.x9;
        var h0 = f0 + g0;
        var h1 = f1 + g1;
        var h2 = f2 + g2;
        var h3 = f3 + g3;
        var h4 = f4 + g4;
        var h5 = f5 + g5;
        var h6 = f6 + g6;
        var h7 = f7 + g7;
        var h8 = f8 + g8;
        var h9 = f9 + g9;

        h = new(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    public static void fe_sq(out FieldElement h, ref FieldElement f)
    {
        var f0 = f.x0;
        var f1 = f.x1;
        var f2 = f.x2;
        var f3 = f.x3;
        var f4 = f.x4;
        var f5 = f.x5;
        var f6 = f.x6;
        var f7 = f.x7;
        var f8 = f.x8;
        var f9 = f.x9;
        var f0_2 = 2 * f0;
        var f1_2 = 2 * f1;
        var f2_2 = 2 * f2;
        var f3_2 = 2 * f3;
        var f4_2 = 2 * f4;
        var f5_2 = 2 * f5;
        var f6_2 = 2 * f6;
        var f7_2 = 2 * f7;
        var f5_38 = 38 * f5;
        var f6_19 = 19 * f6;
        var f7_38 = 38 * f7;
        var f8_19 = 19 * f8;
        var f9_38 = 38 * f9;
        long f0f0 = f0 * (long)f0;
        long f0f1_2 = f0_2 * (long)f1;
        long f0f2_2 = f0_2 * (long)f2;
        long f0f3_2 = f0_2 * (long)f3;
        long f0f4_2 = f0_2 * (long)f4;
        long f0f5_2 = f0_2 * (long)f5;
        long f0f6_2 = f0_2 * (long)f6;
        long f0f7_2 = f0_2 * (long)f7;
        long f0f8_2 = f0_2 * (long)f8;
        long f0f9_2 = f0_2 * (long)f9;
        long f1f1_2 = f1_2 * (long)f1;
        long f1f2_2 = f1_2 * (long)f2;
        long f1f3_4 = f1_2 * (long)f3_2;
        long f1f4_2 = f1_2 * (long)f4;
        long f1f5_4 = f1_2 * (long)f5_2;
        long f1f6_2 = f1_2 * (long)f6;
        long f1f7_4 = f1_2 * (long)f7_2;
        long f1f8_2 = f1_2 * (long)f8;
        long f1f9_76 = f1_2 * (long)f9_38;
        long f2f2 = f2 * (long)f2;
        long f2f3_2 = f2_2 * (long)f3;
        long f2f4_2 = f2_2 * (long)f4;
        long f2f5_2 = f2_2 * (long)f5;
        long f2f6_2 = f2_2 * (long)f6;
        long f2f7_2 = f2_2 * (long)f7;
        long f2f8_38 = f2_2 * (long)f8_19;
        long f2f9_38 = f2 * (long)f9_38;
        long f3f3_2 = f3_2 * (long)f3;
        long f3f4_2 = f3_2 * (long)f4;
        long f3f5_4 = f3_2 * (long)f5_2;
        long f3f6_2 = f3_2 * (long)f6;
        long f3f7_76 = f3_2 * (long)f7_38;
        long f3f8_38 = f3_2 * (long)f8_19;
        long f3f9_76 = f3_2 * (long)f9_38;
        long f4f4 = f4 * (long)f4;
        long f4f5_2 = f4_2 * (long)f5;
        long f4f6_38 = f4_2 * (long)f6_19;
        long f4f7_38 = f4 * (long)f7_38;
        long f4f8_38 = f4_2 * (long)f8_19;
        long f4f9_38 = f4 * (long)f9_38;
        long f5f5_38 = f5 * (long)f5_38;
        long f5f6_38 = f5_2 * (long)f6_19;
        long f5f7_76 = f5_2 * (long)f7_38;
        long f5f8_38 = f5_2 * (long)f8_19;
        long f5f9_76 = f5_2 * (long)f9_38;
        long f6f6_19 = f6 * (long)f6_19;
        long f6f7_38 = f6 * (long)f7_38;
        long f6f8_38 = f6_2 * (long)f8_19;
        long f6f9_38 = f6 * (long)f9_38;
        long f7f7_38 = f7 * (long)f7_38;
        long f7f8_38 = f7_2 * (long)f8_19;
        long f7f9_76 = f7_2 * (long)f9_38;
        long f8f8_19 = f8 * (long)f8_19;
        long f8f9_38 = f8 * (long)f9_38;
        long f9f9_38 = f9 * (long)f9_38;
        long h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
        long h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
        long h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        carry0 = (h0 + (long)(1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        carry4 = (h4 + (long)(1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        carry1 = (h1 + (long)(1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        carry5 = (h5 + (long)(1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        carry2 = (h2 + (long)(1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        carry6 = (h6 + (long)(1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        carry3 = (h3 + (long)(1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        carry7 = (h7 + (long)(1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        carry4 = (h4 + (long)(1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        carry8 = (h8 + (long)(1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        carry9 = (h9 + (long)(1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        carry0 = (h0 + (long)(1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        h = new((nint)h0, (nint)h1, (nint)h2, (nint)h3, (nint)h4, (nint)h5, (nint)h6, (nint)h7, (nint)h8, (nint)h9);
    }

    public static void fe_sq2(out FieldElement h, ref FieldElement f)
    {
        var f0 = f.x0;
        var f1 = f.x1;
        var f2 = f.x2;
        var f3 = f.x3;
        var f4 = f.x4;
        var f5 = f.x5;
        var f6 = f.x6;
        var f7 = f.x7;
        var f8 = f.x8;
        var f9 = f.x9;
        var f0_2 = 2 * f0;
        var f1_2 = 2 * f1;
        var f2_2 = 2 * f2;
        var f3_2 = 2 * f3;
        var f4_2 = 2 * f4;
        var f5_2 = 2 * f5;
        var f6_2 = 2 * f6;
        var f7_2 = 2 * f7;
        var f5_38 = 38 * f5; /* 1.959375*2^30 */
        var f6_19 = 19 * f6; /* 1.959375*2^30 */
        var f7_38 = 38 * f7; /* 1.959375*2^30 */
        var f8_19 = 19 * f8; /* 1.959375*2^30 */
        var f9_38 = 38 * f9; /* 1.959375*2^30 */
        long f0f0 = f0 * (long)f0;
        long f0f1_2 = f0_2 * (long)f1;
        long f0f2_2 = f0_2 * (long)f2;
        long f0f3_2 = f0_2 * (long)f3;
        long f0f4_2 = f0_2 * (long)f4;
        long f0f5_2 = f0_2 * (long)f5;
        long f0f6_2 = f0_2 * (long)f6;
        long f0f7_2 = f0_2 * (long)f7;
        long f0f8_2 = f0_2 * (long)f8;
        long f0f9_2 = f0_2 * (long)f9;
        long f1f1_2 = f1_2 * (long)f1;
        long f1f2_2 = f1_2 * (long)f2;
        long f1f3_4 = f1_2 * (long)f3_2;
        long f1f4_2 = f1_2 * (long)f4;
        long f1f5_4 = f1_2 * (long)f5_2;
        long f1f6_2 = f1_2 * (long)f6;
        long f1f7_4 = f1_2 * (long)f7_2;
        long f1f8_2 = f1_2 * (long)f8;
        long f1f9_76 = f1_2 * (long)f9_38;
        long f2f2 = f2 * (long)f2;
        long f2f3_2 = f2_2 * (long)f3;
        long f2f4_2 = f2_2 * (long)f4;
        long f2f5_2 = f2_2 * (long)f5;
        long f2f6_2 = f2_2 * (long)f6;
        long f2f7_2 = f2_2 * (long)f7;
        long f2f8_38 = f2_2 * (long)f8_19;
        long f2f9_38 = f2 * (long)f9_38;
        long f3f3_2 = f3_2 * (long)f3;
        long f3f4_2 = f3_2 * (long)f4;
        long f3f5_4 = f3_2 * (long)f5_2;
        long f3f6_2 = f3_2 * (long)f6;
        long f3f7_76 = f3_2 * (long)f7_38;
        long f3f8_38 = f3_2 * (long)f8_19;
        long f3f9_76 = f3_2 * (long)f9_38;
        long f4f4 = f4 * (long)f4;
        long f4f5_2 = f4_2 * (long)f5;
        long f4f6_38 = f4_2 * (long)f6_19;
        long f4f7_38 = f4 * (long)f7_38;
        long f4f8_38 = f4_2 * (long)f8_19;
        long f4f9_38 = f4 * (long)f9_38;
        long f5f5_38 = f5 * (long)f5_38;
        long f5f6_38 = f5_2 * (long)f6_19;
        long f5f7_76 = f5_2 * (long)f7_38;
        long f5f8_38 = f5_2 * (long)f8_19;
        long f5f9_76 = f5_2 * (long)f9_38;
        long f6f6_19 = f6 * (long)f6_19;
        long f6f7_38 = f6 * (long)f7_38;
        long f6f8_38 = f6_2 * (long)f8_19;
        long f6f9_38 = f6 * (long)f9_38;
        long f7f7_38 = f7 * (long)f7_38;
        long f7f8_38 = f7_2 * (long)f8_19;
        long f7f9_76 = f7_2 * (long)f9_38;
        long f8f8_19 = f8 * (long)f8_19;
        long f8f9_38 = f8 * (long)f9_38;
        long f9f9_38 = f9 * (long)f9_38;
        long h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
        long h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
        long h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        h0 += h0;
        h1 += h1;
        h2 += h2;
        h3 += h3;
        h4 += h4;
        h5 += h5;
        h6 += h6;
        h7 += h7;
        h8 += h8;
        h9 += h9;

        carry0 = (h0 + (long)(1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        carry4 = (h4 + (long)(1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        carry1 = (h1 + (long)(1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        carry5 = (h5 + (long)(1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        carry2 = (h2 + (long)(1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        carry6 = (h6 + (long)(1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        carry3 = (h3 + (long)(1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        carry7 = (h7 + (long)(1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        carry4 = (h4 + (long)(1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        carry8 = (h8 + (long)(1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        carry9 = (h9 + (long)(1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        carry0 = (h0 + (long)(1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        h = new((nint)h0, (nint)h1, (nint)h2, (nint)h3, (nint)h4, (nint)h5, (nint)h6, (nint)h7, (nint)h8, (nint)h9);
    }

    public static void fe_sub(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {
        var f0 = f.x0;
        var f1 = f.x1;
        var f2 = f.x2;
        var f3 = f.x3;
        var f4 = f.x4;
        var f5 = f.x5;
        var f6 = f.x6;
        var f7 = f.x7;
        var f8 = f.x8;
        var f9 = f.x9;
        var g0 = g.x0;
        var g1 = g.x1;
        var g2 = g.x2;
        var g3 = g.x3;
        var g4 = g.x4;
        var g5 = g.x5;
        var g6 = g.x6;
        var g7 = g.x7;
        var g8 = g.x8;
        var g9 = g.x9;
        var h0 = f0 - g0;
        var h1 = f1 - g1;
        var h2 = f2 - g2;
        var h3 = f3 - g3;
        var h4 = f4 - g4;
        var h5 = f5 - g5;
        var h6 = f6 - g6;
        var h7 = f7 - g7;
        var h8 = f8 - g8;
        var h9 = f9 - g9;

        h = new(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    public static void fe_mul(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {
        var f0 = f.x0;
        var f1 = f.x1;
        var f2 = f.x2;
        var f3 = f.x3;
        var f4 = f.x4;
        var f5 = f.x5;
        var f6 = f.x6;
        var f7 = f.x7;
        var f8 = f.x8;
        var f9 = f.x9;
        var g0 = g.x0;
        var g1 = g.x1;
        var g2 = g.x2;
        var g3 = g.x3;
        var g4 = g.x4;
        var g5 = g.x5;
        var g6 = g.x6;
        var g7 = g.x7;
        var g8 = g.x8;
        var g9 = g.x9;
        var g1_19 = 19 * g1; /* 1.959375*2^29 */
        var g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
        var g3_19 = 19 * g3;
        var g4_19 = 19 * g4;
        var g5_19 = 19 * g5;
        var g6_19 = 19 * g6;
        var g7_19 = 19 * g7;
        var g8_19 = 19 * g8;
        var g9_19 = 19 * g9;
        var f1_2 = 2 * f1;
        var f3_2 = 2 * f3;
        var f5_2 = 2 * f5;
        var f7_2 = 2 * f7;
        var f9_2 = 2 * f9;
        long f0g0 = f0 * (long)g0;
        long f0g1 = f0 * (long)g1;
        long f0g2 = f0 * (long)g2;
        long f0g3 = f0 * (long)g3;
        long f0g4 = f0 * (long)g4;
        long f0g5 = f0 * (long)g5;
        long f0g6 = f0 * (long)g6;
        long f0g7 = f0 * (long)g7;
        long f0g8 = f0 * (long)g8;
        long f0g9 = f0 * (long)g9;
        long f1g0 = f1 * (long)g0;
        long f1g1_2 = f1_2 * (long)g1;
        long f1g2 = f1 * (long)g2;
        long f1g3_2 = f1_2 * (long)g3;
        long f1g4 = f1 * (long)g4;
        long f1g5_2 = f1_2 * (long)g5;
        long f1g6 = f1 * (long)g6;
        long f1g7_2 = f1_2 * (long)g7;
        long f1g8 = f1 * (long)g8;
        long f1g9_38 = f1_2 * (long)g9_19;
        long f2g0 = f2 * (long)g0;
        long f2g1 = f2 * (long)g1;
        long f2g2 = f2 * (long)g2;
        long f2g3 = f2 * (long)g3;
        long f2g4 = f2 * (long)g4;
        long f2g5 = f2 * (long)g5;
        long f2g6 = f2 * (long)g6;
        long f2g7 = f2 * (long)g7;
        long f2g8_19 = f2 * (long)g8_19;
        long f2g9_19 = f2 * (long)g9_19;
        long f3g0 = f3 * (long)g0;
        long f3g1_2 = f3_2 * (long)g1;
        long f3g2 = f3 * (long)g2;
        long f3g3_2 = f3_2 * (long)g3;
        long f3g4 = f3 * (long)g4;
        long f3g5_2 = f3_2 * (long)g5;
        long f3g6 = f3 * (long)g6;
        long f3g7_38 = f3_2 * (long)g7_19;
        long f3g8_19 = f3 * (long)g8_19;
        long f3g9_38 = f3_2 * (long)g9_19;
        long f4g0 = f4 * (long)g0;
        long f4g1 = f4 * (long)g1;
        long f4g2 = f4 * (long)g2;
        long f4g3 = f4 * (long)g3;
        long f4g4 = f4 * (long)g4;
        long f4g5 = f4 * (long)g5;
        long f4g6_19 = f4 * (long)g6_19;
        long f4g7_19 = f4 * (long)g7_19;
        long f4g8_19 = f4 * (long)g8_19;
        long f4g9_19 = f4 * (long)g9_19;
        long f5g0 = f5 * (long)g0;
        long f5g1_2 = f5_2 * (long)g1;
        long f5g2 = f5 * (long)g2;
        long f5g3_2 = f5_2 * (long)g3;
        long f5g4 = f5 * (long)g4;
        long f5g5_38 = f5_2 * (long)g5_19;
        long f5g6_19 = f5 * (long)g6_19;
        long f5g7_38 = f5_2 * (long)g7_19;
        long f5g8_19 = f5 * (long)g8_19;
        long f5g9_38 = f5_2 * (long)g9_19;
        long f6g0 = f6 * (long)g0;
        long f6g1 = f6 * (long)g1;
        long f6g2 = f6 * (long)g2;
        long f6g3 = f6 * (long)g3;
        long f6g4_19 = f6 * (long)g4_19;
        long f6g5_19 = f6 * (long)g5_19;
        long f6g6_19 = f6 * (long)g6_19;
        long f6g7_19 = f6 * (long)g7_19;
        long f6g8_19 = f6 * (long)g8_19;
        long f6g9_19 = f6 * (long)g9_19;
        long f7g0 = f7 * (long)g0;
        long f7g1_2 = f7_2 * (long)g1;
        long f7g2 = f7 * (long)g2;
        long f7g3_38 = f7_2 * (long)g3_19;
        long f7g4_19 = f7 * (long)g4_19;
        long f7g5_38 = f7_2 * (long)g5_19;
        long f7g6_19 = f7 * (long)g6_19;
        long f7g7_38 = f7_2 * (long)g7_19;
        long f7g8_19 = f7 * (long)g8_19;
        long f7g9_38 = f7_2 * (long)g9_19;
        long f8g0 = f8 * (long)g0;
        long f8g1 = f8 * (long)g1;
        long f8g2_19 = f8 * (long)g2_19;
        long f8g3_19 = f8 * (long)g3_19;
        long f8g4_19 = f8 * (long)g4_19;
        long f8g5_19 = f8 * (long)g5_19;
        long f8g6_19 = f8 * (long)g6_19;
        long f8g7_19 = f8 * (long)g7_19;
        long f8g8_19 = f8 * (long)g8_19;
        long f8g9_19 = f8 * (long)g9_19;
        long f9g0 = f9 * (long)g0;
        long f9g1_38 = f9_2 * (long)g1_19;
        long f9g2_19 = f9 * (long)g2_19;
        long f9g3_38 = f9_2 * (long)g3_19;
        long f9g4_19 = f9 * (long)g4_19;
        long f9g5_38 = f9_2 * (long)g5_19;
        long f9g6_19 = f9 * (long)g6_19;
        long f9g7_38 = f9_2 * (long)g7_19;
        long f9g8_19 = f9 * (long)g8_19;
        long f9g9_38 = f9_2 * (long)g9_19;
        long h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
        long h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
        long h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
        long h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
        long h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
        long h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
        long h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
        long h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
        long h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
        long h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        carry0 = (h0 + (long)(1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        carry4 = (h4 + (long)(1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        carry1 = (h1 + (long)(1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        carry5 = (h5 + (long)(1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        carry2 = (h2 + (long)(1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        carry6 = (h6 + (long)(1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        carry3 = (h3 + (long)(1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        carry7 = (h7 + (long)(1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        carry4 = (h4 + (long)(1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        carry8 = (h8 + (long)(1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        carry9 = (h9 + (long)(1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        carry0 = (h0 + (long)(1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        h = new((nint)h0, (nint)h1, (nint)h2, (nint)h3, (nint)h4, (nint)h5, (nint)h6, (nint)h7, (nint)h8, (nint)h9);
    }

    public static void fe_neg(out FieldElement h, ref FieldElement f)
    {
        var f0 = f.x0;
        var f1 = f.x1;
        var f2 = f.x2;
        var f3 = f.x3;
        var f4 = f.x4;
        var f5 = f.x5;
        var f6 = f.x6;
        var f7 = f.x7;
        var f8 = f.x8;
        var f9 = f.x9;
        var h0 = -f0;
        var h1 = -f1;
        var h2 = -f2;
        var h3 = -f3;
        var h4 = -f4;
        var h5 = -f5;
        var h6 = -f6;
        var h7 = -f7;
        var h8 = -f8;
        var h9 = -f9;

        h = new(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    public static void fe_invert(out FieldElement result, ref FieldElement z)
    {
        FieldElement t0;
        FieldElement t1;
        FieldElement t2;
        FieldElement t3;
        int i;

        fe_sq(out t0, ref z);
        fe_sq(out t1, ref t0);
        for (i = 1; i < 2; ++i)
        {
            fe_sq(out t1, ref t1);
        }

        fe_mul(out t1, ref z, ref t1);

        fe_mul(out t0, ref t0, ref t1);

        fe_sq(out t2, ref t0);
        fe_mul(out t1, ref t1, ref t2);

        fe_sq(out t2, ref t1);
        for (i = 1; i < 5; ++i)
        {
            fe_sq(out t2, ref t2);
        }

        fe_mul(out t1, ref t2, ref t1);

        fe_sq(out t2, ref t1);
        for (i = 1; i < 10; ++i)
        {
            fe_sq(out t2, ref t2);
        }

        fe_mul(out t2, ref t2, ref t1);

        fe_sq(out t3, ref t2);
        for (i = 1; i < 20; ++i)
        {
            fe_sq(out t3, ref t3);
        }

        fe_mul(out t2, ref t3, ref t2);

        fe_sq(out t2, ref t2);
        for (i = 1; i < 10; ++i)
        {
            fe_sq(out t2, ref t2);
        }

        fe_mul(out t1, ref t2, ref t1);

        fe_sq(out t2, ref t1);
        for (i = 1; i < 50; ++i)
        {
            fe_sq(out t2, ref t2);
        }

        fe_mul(out t2, ref t2, ref t1);

        fe_sq(out t3, ref t2);
        for (i = 1; i < 100; ++i)
        {
            fe_sq(out t3, ref t3);
        }

        fe_mul(out t2, ref t3, ref t2);

        fe_sq(out t2, ref t2);
        for (i = 1; i < 50; ++i)
        {
            fe_sq(out t2, ref t2);
        }

        fe_mul(out t1, ref t2, ref t1);

        fe_sq(out t1, ref t1);
        for (i = 1; i < 5; ++i)
        {
            fe_sq(out t1, ref t1);
        }

        fe_mul(out result, ref t1, ref t0);
    }

    public static nint fe_isnegative(ref FieldElement f)
    {
        FieldElement fr;
        fe_reduce(out fr, ref f);
        return fr.x0 & 1;
    }

    public static void fe_tobytes(Span<byte> s, ref FieldElement h)
    {
        FieldElement hr;
        fe_reduce(out hr, ref h);

        var h0 = hr.x0;
        var h1 = hr.x1;
        var h2 = hr.x2;
        var h3 = hr.x3;
        var h4 = hr.x4;
        var h5 = hr.x5;
        var h6 = hr.x6;
        var h7 = hr.x7;
        var h8 = hr.x8;
        var h9 = hr.x9;

        unchecked
        {
            s[0] = (byte)(h0 >> 0);
            s[1] = (byte)(h0 >> 8);
            s[2] = (byte)(h0 >> 16);
            s[3] = (byte)((h0 >> 24) | (h1 << 2));
            s[4] = (byte)(h1 >> 6);
            s[5] = (byte)(h1 >> 14);
            s[6] = (byte)((h1 >> 22) | (h2 << 3));
            s[7] = (byte)(h2 >> 5);
            s[8] = (byte)(h2 >> 13);
            s[9] = (byte)((h2 >> 21) | (h3 << 5));
            s[10] = (byte)(h3 >> 3);
            s[11] = (byte)(h3 >> 11);
            s[12] = (byte)((h3 >> 19) | (h4 << 6));
            s[13] = (byte)(h4 >> 2);
            s[14] = (byte)(h4 >> 10);
            s[15] = (byte)(h4 >> 18);
            s[16] = (byte)(h5 >> 0);
            s[17] = (byte)(h5 >> 8);
            s[18] = (byte)(h5 >> 16);
            s[19] = (byte)((h5 >> 24) | (h6 << 1));
            s[20] = (byte)(h6 >> 7);
            s[21] = (byte)(h6 >> 15);
            s[22] = (byte)((h6 >> 23) | (h7 << 3));
            s[23] = (byte)(h7 >> 5);
            s[24] = (byte)(h7 >> 13);
            s[25] = (byte)((h7 >> 21) | (h8 << 4));
            s[26] = (byte)(h8 >> 4);
            s[27] = (byte)(h8 >> 12);
            s[28] = (byte)((h8 >> 20) | (h9 << 6));
            s[29] = (byte)(h9 >> 2);
            s[30] = (byte)(h9 >> 10);
            s[31] = (byte)(h9 >> 18);
        }
    }

    public static void fe_reduce(out FieldElement hr, ref FieldElement h)
    {
        var h0 = h.x0;
        var h1 = h.x1;
        var h2 = h.x2;
        var h3 = h.x3;
        var h4 = h.x4;
        var h5 = h.x5;
        var h6 = h.x6;
        var h7 = h.x7;
        var h8 = h.x8;
        var h9 = h.x9;

        var q = ((19 * h9) + (((int)1) << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        h0 += 19 * q;

        var carry0 = h0 >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        var carry1 = h1 >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        var carry2 = h2 >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        var carry3 = h3 >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        var carry4 = h4 >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        var carry5 = h5 >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;
        var carry6 = h6 >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;
        var carry7 = h7 >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;
        var carry8 = h8 >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;
        var carry9 = h9 >> 25;
        h9 -= carry9 << 25;

        hr = new(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }
}
