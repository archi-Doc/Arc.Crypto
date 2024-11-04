// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using BenchmarkDotNet.Attributes;

#pragma warning disable SA1300 // Element should begin with upper-case letter
#pragma warning disable SA1307 // Accessible fields should begin with upper-case letter
#pragma warning disable SA1405 // Debug.Assert should provide message text

namespace Benchmark;

public struct FieldElement : IEquatable<FieldElement>
{
    public int x0;
    public int x1;
    public int x2;
    public int x3;
    public int x4;
    public int x5;
    public int x6;
    public int x7;
    public int x8;
    public int x9;

    public FieldElement(int e0, int e1, int e2, int e3, int e4, int e5, int e6, int e7, int e8, int e9)
    {
        this.x0 = e0;
        this.x1 = e1;
        this.x2 = e2;
        this.x3 = e3;
        this.x4 = e4;
        this.x5 = e5;
        this.x6 = e6;
        this.x7 = e7;
        this.x8 = e8;
        this.x9 = e9;
    }

    public bool Equals(FieldElement other)
    {
        return this.x0 == other.x0 && this.x1 == other.x1 && this.x2 == other.x2 && this.x3 == other.x3 &&
               this.x4 == other.x4 && this.x5 == other.x5 && this.x6 == other.x6 && this.x7 == other.x7 &&
               this.x8 == other.x8 && this.x9 == other.x9;
    }
}

public static class Avx2Methods
{
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

        h.x0 = h0;
        h.x1 = h1;
        h.x2 = h2;
        h.x3 = h3;
        h.x4 = h4;
        h.x5 = h5;
        h.x6 = h6;
        h.x7 = h7;
        h.x8 = h8;
        h.x9 = h9;
    }

    public static void fe_add2(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {
        h.x0 = f.x0 + g.x0;
        h.x1 = f.x1 + g.x1;
        h.x2 = f.x2 + g.x2;
        h.x3 = f.x3 + g.x3;
        h.x4 = f.x4 + g.x4;
        h.x5 = f.x5 + g.x5;
        h.x6 = f.x6 + g.x6;
        h.x7 = f.x7 + g.x7;
        h.x8 = f.x8 + g.x8;
        h.x9 = f.x9 + g.x9;
    }

    public static unsafe void fe_add3(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {
        h = default;
        fixed (int* ptr_f = &f.x0)
        {
            fixed (int* ptr_g = &g.x0)
            {
                fixed (int* ptr_h = &h.x0)
                {
                    var vec_f = Avx.LoadVector256(ptr_f);
                    var vec_g = Avx.LoadVector256(ptr_g);
                    var vec_h = vec_f + vec_g;

                    vec_h.StoreUnsafe(ref Unsafe.AsRef<int>(ptr_h));
                }
            }
        }

        h.x8 = f.x8 + g.x8;
        h.x9 = f.x9 + g.x9;
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
        var f0f0 = f0 * (long)f0;
        var f0f1_2 = f0_2 * (long)f1;
        var f0f2_2 = f0_2 * (long)f2;
        var f0f3_2 = f0_2 * (long)f3;
        var f0f4_2 = f0_2 * (long)f4;
        var f0f5_2 = f0_2 * (long)f5;
        var f0f6_2 = f0_2 * (long)f6;
        var f0f7_2 = f0_2 * (long)f7;
        var f0f8_2 = f0_2 * (long)f8;
        var f0f9_2 = f0_2 * (long)f9;
        var f1f1_2 = f1_2 * (long)f1;
        var f1f2_2 = f1_2 * (long)f2;
        var f1f3_4 = f1_2 * (long)f3_2;
        var f1f4_2 = f1_2 * (long)f4;
        var f1f5_4 = f1_2 * (long)f5_2;
        var f1f6_2 = f1_2 * (long)f6;
        var f1f7_4 = f1_2 * (long)f7_2;
        var f1f8_2 = f1_2 * (long)f8;
        var f1f9_76 = f1_2 * (long)f9_38;
        var f2f2 = f2 * (long)f2;
        var f2f3_2 = f2_2 * (long)f3;
        var f2f4_2 = f2_2 * (long)f4;
        var f2f5_2 = f2_2 * (long)f5;
        var f2f6_2 = f2_2 * (long)f6;
        var f2f7_2 = f2_2 * (long)f7;
        var f2f8_38 = f2_2 * (long)f8_19;
        var f2f9_38 = f2 * (long)f9_38;
        var f3f3_2 = f3_2 * (long)f3;
        var f3f4_2 = f3_2 * (long)f4;
        var f3f5_4 = f3_2 * (long)f5_2;
        var f3f6_2 = f3_2 * (long)f6;
        var f3f7_76 = f3_2 * (long)f7_38;
        var f3f8_38 = f3_2 * (long)f8_19;
        var f3f9_76 = f3_2 * (long)f9_38;
        var f4f4 = f4 * (long)f4;
        var f4f5_2 = f4_2 * (long)f5;
        var f4f6_38 = f4_2 * (long)f6_19;
        var f4f7_38 = f4 * (long)f7_38;
        var f4f8_38 = f4_2 * (long)f8_19;
        var f4f9_38 = f4 * (long)f9_38;
        var f5f5_38 = f5 * (long)f5_38;
        var f5f6_38 = f5_2 * (long)f6_19;
        var f5f7_76 = f5_2 * (long)f7_38;
        var f5f8_38 = f5_2 * (long)f8_19;
        var f5f9_76 = f5_2 * (long)f9_38;
        var f6f6_19 = f6 * (long)f6_19;
        var f6f7_38 = f6 * (long)f7_38;
        var f6f8_38 = f6_2 * (long)f8_19;
        var f6f9_38 = f6 * (long)f9_38;
        var f7f7_38 = f7 * (long)f7_38;
        var f7f8_38 = f7_2 * (long)f8_19;
        var f7f9_76 = f7_2 * (long)f9_38;
        var f8f8_19 = f8 * (long)f8_19;
        var f8f9_38 = f8 * (long)f9_38;
        var f9f9_38 = f9 * (long)f9_38;
        var h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        var h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        var h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        var h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
        var h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
        var h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
        var h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
        var h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
        var h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
        var h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

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

        carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        carry1 = (h1 + (1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;

        carry5 = (h5 + (1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        carry2 = (h2 + (1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;

        carry6 = (h6 + (1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        carry3 = (h3 + (1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;

        carry7 = (h7 + (1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        carry8 = (h8 + (1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        carry9 = (h9 + (1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        h.x0 = (int)h0;
        h.x1 = (int)h1;
        h.x2 = (int)h2;
        h.x3 = (int)h3;
        h.x4 = (int)h4;
        h.x5 = (int)h5;
        h.x6 = (int)h6;
        h.x7 = (int)h7;
        h.x8 = (int)h8;
        h.x9 = (int)h9;
    }

    public static unsafe void fe_sqB(out FieldElement h, ref FieldElement f)
    {// 140
        var f0_2 = (long)f.x0 << 1;
        var f1_2 = (long)f.x1 << 1;
        var f2_2 = (long)f.x2 << 1;
        var f3_2 = (long)f.x3 << 1;
        var f4_2 = (long)f.x4 << 1;
        var f5_2 = (long)f.x5 << 1;
        var f6_2 = (long)f.x6 << 1;
        var f7_2 = (long)f.x7 << 1;

        var f5_38 = 38 * (long)f.x5;
        var f6_19 = 19 * (long)f.x6;
        var f7_38 = 38 * (long)f.x7;
        var f8_19 = 19 * (long)f.x8;
        var f9_38 = 38 * (long)f.x9;

        /*var vec_f0_2 = Vector256.Create(f0_2);
        Span<int> stack_fm = stackalloc int[8];
        fixed (int* ptr29 = &f.x2)
        {
            var vec_f29 = Avx.LoadVector256(ptr29);
            var vec_fm = vec_3819 * vec_f29;
            vec_fm.StoreUnsafe(ref MemoryMarshal.GetReference(stack_fm));
        }*/

        /*var vec1 = Vector256.Create(f.x0, 0, f0_2, 0, f0_2, 0, f0_2, 0);
        var vec2 = Vector256.Create(f.x0, 0, f1, 0, f2, 0, f3, 0);
        var vec_acc = Avx2.Multiply(vec1, vec2);

        vec1 = Vector256.Create(f1_2, 0, f2, 0, f1_2, 0, f1_2, 0);
        vec2 = Vector256.Create(f9_38, 0, f9_38, 0, f1, 0, f2, 0);
        vec_acc = Vector256.Add(vec_acc, Avx2.Multiply(vec1, vec2));

        vec1 = Vector256.Create(f2_2, 0, f3_2, 0, f3_2, 0, f4, 0);
        vec2 = Vector256.Create(f8_19, 0, f8_19, 0, f9_38, 0, f9_38, 0);
        vec_acc = Vector256.Add(vec_acc, Avx2.Multiply(vec1, vec2));

        vec1 = Vector256.Create(f3_2, 0, f4, 0, f4_2, 0, f5_2, 0);
        vec2 = Vector256.Create(f7_38, 0, f7_38, 0, f8_19, 0, f8_19, 0);
        vec_acc = Vector256.Add(vec_acc, Avx2.Multiply(vec1, vec2));

        vec1 = Vector256.Create(f4_2, 0, f5_2, 0, f5_2, 0, f6, 0);
        vec2 = Vector256.Create(f6_19, 0, f6_19, 0, f7_38, 0, f7_38, 0);
        vec_acc = Vector256.Add(vec_acc, Avx2.Multiply(vec1, vec2));

        vec1 = Vector256.Create(f5, 0, 0, 0, f6, 0, 0, 0);
        vec2 = Vector256.Create(f5_38, 0, 0, 0, f6_19, 0, 0, 0);
        vec_acc = Vector256.Add(vec_acc, Avx2.Multiply(vec1, vec2));

        var h0 = vec_acc[0];
        var h1 = vec_acc[1];
        var h2 = vec_acc[2];
        var h3 = vec_acc[3];*/

        var h0 = (f.x0 * (long)f.x0) + (f1_2 * f9_38) + (f2_2 * f8_19) + (f3_2 * f7_38) + (f4_2 * f6_19) + (f.x5 * f5_38);
        var h1 = (f0_2 * f.x1) + (f.x2 * f9_38) + (f3_2 * f8_19) + (f.x4 * f7_38) + (f5_2 * f6_19);
        var h2 = (f0_2 * f.x2) + (f1_2 * f.x1) + (f3_2 * f9_38) + (f4_2 * f8_19) + (f5_2 * f7_38) + (f.x6 * f6_19);
        var h3 = (f0_2 * f.x3) + (f1_2 * f.x2) + (f.x4 * f9_38) + (f5_2 * f8_19) + (f.x6 * f7_38);
        var h4 = (f0_2 * f.x4) + (f1_2 * f3_2) + (f.x2 * (long)f.x2) + (f5_2 * f9_38) + (f6_2 * f8_19) + (f.x7 * f7_38);
        var h5 = (f0_2 * f.x5) + (f1_2 * f.x4) + (f2_2 * f.x3) + (f.x6 * f9_38) + (f7_2 * f8_19);
        var h6 = (f0_2 * f.x6) + (f1_2 * f5_2) + (f2_2 * f.x4) + (f3_2 * f.x3) + (f7_2 * f9_38) + (f.x8 * f8_19);
        var h7 = (f0_2 * f.x7) + (f1_2 * f.x6) + (f2_2 * f.x5) + (f3_2 * f.x4) + (f.x8 * f9_38);
        var h8 = (f0_2 * f.x8) + (f1_2 * f7_2) + (f2_2 * f.x6) + (f3_2 * f5_2) + (f.x4 * (long)f.x4) + (f.x9 * f9_38);
        var h9 = (f0_2 * f.x9) + (f1_2 * f.x8) + (f2_2 * f.x7) + (f3_2 * f.x6) + (f4_2 * f.x5);

        const long r24 = 1 << 24;
        const long r25 = 1 << 25;

        long carry0 = (h0 + r25) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        long carry4 = (h4 + r25) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        long carry1 = (h1 + r24) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;

        long carry5 = (h5 + r24) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        long carry2 = (h2 + r25) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;

        long carry6 = (h6 + r25) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        long carry3 = (h3 + r24) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;

        long carry7 = (h7 + r24) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        carry4 = (h4 + r25) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        long carry8 = (h8 + r25) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        long carry9 = (h9 + r24) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        carry0 = (h0 + r25) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        h.x0 = (int)h0;
        h.x1 = (int)h1;
        h.x2 = (int)h2;
        h.x3 = (int)h3;
        h.x4 = (int)h4;
        h.x5 = (int)h5;
        h.x6 = (int)h6;
        h.x7 = (int)h7;
        h.x8 = (int)h8;
        h.x9 = (int)h9;
    }

    public static void fe_mul_original(out FieldElement h, ref FieldElement f, ref FieldElement g)
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
        var g1_19 = 19 * g1;
        var g2_19 = 19 * g2;
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
        var f0g0 = f0 * (long)g0;
        var f0g1 = f0 * (long)g1;
        var f0g2 = f0 * (long)g2;
        var f0g3 = f0 * (long)g3;
        var f0g4 = f0 * (long)g4;
        var f0g5 = f0 * (long)g5;
        var f0g6 = f0 * (long)g6;
        var f0g7 = f0 * (long)g7;
        var f0g8 = f0 * (long)g8;
        var f0g9 = f0 * (long)g9;
        var f1g0 = f1 * (long)g0;
        var f1g1_2 = f1_2 * (long)g1;
        var f1g2 = f1 * (long)g2;
        var f1g3_2 = f1_2 * (long)g3;
        var f1g4 = f1 * (long)g4;
        var f1g5_2 = f1_2 * (long)g5;
        var f1g6 = f1 * (long)g6;
        var f1g7_2 = f1_2 * (long)g7;
        var f1g8 = f1 * (long)g8;
        var f1g9_38 = f1_2 * (long)g9_19;
        var f2g0 = f2 * (long)g0;
        var f2g1 = f2 * (long)g1;
        var f2g2 = f2 * (long)g2;
        var f2g3 = f2 * (long)g3;
        var f2g4 = f2 * (long)g4;
        var f2g5 = f2 * (long)g5;
        var f2g6 = f2 * (long)g6;
        var f2g7 = f2 * (long)g7;
        var f2g8_19 = f2 * (long)g8_19;
        var f2g9_19 = f2 * (long)g9_19;
        var f3g0 = f3 * (long)g0;
        var f3g1_2 = f3_2 * (long)g1;
        var f3g2 = f3 * (long)g2;
        var f3g3_2 = f3_2 * (long)g3;
        var f3g4 = f3 * (long)g4;
        var f3g5_2 = f3_2 * (long)g5;
        var f3g6 = f3 * (long)g6;
        var f3g7_38 = f3_2 * (long)g7_19;
        var f3g8_19 = f3 * (long)g8_19;
        var f3g9_38 = f3_2 * (long)g9_19;
        var f4g0 = f4 * (long)g0;
        var f4g1 = f4 * (long)g1;
        var f4g2 = f4 * (long)g2;
        var f4g3 = f4 * (long)g3;
        var f4g4 = f4 * (long)g4;
        var f4g5 = f4 * (long)g5;
        var f4g6_19 = f4 * (long)g6_19;
        var f4g7_19 = f4 * (long)g7_19;
        var f4g8_19 = f4 * (long)g8_19;
        var f4g9_19 = f4 * (long)g9_19;
        var f5g0 = f5 * (long)g0;
        var f5g1_2 = f5_2 * (long)g1;
        var f5g2 = f5 * (long)g2;
        var f5g3_2 = f5_2 * (long)g3;
        var f5g4 = f5 * (long)g4;
        var f5g5_38 = f5_2 * (long)g5_19;
        var f5g6_19 = f5 * (long)g6_19;
        var f5g7_38 = f5_2 * (long)g7_19;
        var f5g8_19 = f5 * (long)g8_19;
        var f5g9_38 = f5_2 * (long)g9_19;
        var f6g0 = f6 * (long)g0;
        var f6g1 = f6 * (long)g1;
        var f6g2 = f6 * (long)g2;
        var f6g3 = f6 * (long)g3;
        var f6g4_19 = f6 * (long)g4_19;
        var f6g5_19 = f6 * (long)g5_19;
        var f6g6_19 = f6 * (long)g6_19;
        var f6g7_19 = f6 * (long)g7_19;
        var f6g8_19 = f6 * (long)g8_19;
        var f6g9_19 = f6 * (long)g9_19;
        var f7g0 = f7 * (long)g0;
        var f7g1_2 = f7_2 * (long)g1;
        var f7g2 = f7 * (long)g2;
        var f7g3_38 = f7_2 * (long)g3_19;
        var f7g4_19 = f7 * (long)g4_19;
        var f7g5_38 = f7_2 * (long)g5_19;
        var f7g6_19 = f7 * (long)g6_19;
        var f7g7_38 = f7_2 * (long)g7_19;
        var f7g8_19 = f7 * (long)g8_19;
        var f7g9_38 = f7_2 * (long)g9_19;
        var f8g0 = f8 * (long)g0;
        var f8g1 = f8 * (long)g1;
        var f8g2_19 = f8 * (long)g2_19;
        var f8g3_19 = f8 * (long)g3_19;
        var f8g4_19 = f8 * (long)g4_19;
        var f8g5_19 = f8 * (long)g5_19;
        var f8g6_19 = f8 * (long)g6_19;
        var f8g7_19 = f8 * (long)g7_19;
        var f8g8_19 = f8 * (long)g8_19;
        var f8g9_19 = f8 * (long)g9_19;
        var f9g0 = f9 * (long)g0;
        var f9g1_38 = f9_2 * (long)g1_19;
        var f9g2_19 = f9 * (long)g2_19;
        var f9g3_38 = f9_2 * (long)g3_19;
        var f9g4_19 = f9 * (long)g4_19;
        var f9g5_38 = f9_2 * (long)g5_19;
        var f9g6_19 = f9 * (long)g6_19;
        var f9g7_38 = f9_2 * (long)g7_19;
        var f9g8_19 = f9 * (long)g8_19;
        var f9g9_38 = f9_2 * (long)g9_19;
        var h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
        var h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
        var h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
        var h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
        var h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
        var h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
        var h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
        var h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
        var h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
        var h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
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

        h.x0 = (int)h0;
        h.x1 = (int)h1;
        h.x2 = (int)h2;
        h.x3 = (int)h3;
        h.x4 = (int)h4;
        h.x5 = (int)h5;
        h.x6 = (int)h6;
        h.x7 = (int)h7;
        h.x8 = (int)h8;
        h.x9 = (int)h9;
    }

    public static unsafe void fe_mul(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {// 245
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
        /*var g1_19 = 19 * g1;
        var g2_19 = 19 * g2;
        var g3_19 = 19 * g3;
        var g4_19 = 19 * g4;
        var g5_19 = 19 * g5;
        var g6_19 = 19 * g6;
        var g7_19 = 19 * g7;
        var g8_19 = 19 * g8;*/
        var g9_19 = 19 * g9;

        Vector256<int> vec_g;
        fixed (int* ptr = &g.x1)
        {
            vec_g = Avx.LoadVector256(ptr);
        }

        var vec_19 = Vector256.Create(19);
        var vec_g19 = vec_g * vec_19;
        Span<int> stack_g19 = stackalloc int[8];
        vec_g19.StoreUnsafe(ref MemoryMarshal.GetReference(stack_g19));

        var f1_2 = 2 * (long)f.x1;
        var f3_2 = 2 * (long)f.x3;
        var f5_2 = 2 * (long)f.x5;
        var f7_2 = 2 * (long)f.x7;
        var f9_2 = 2 * (long)f.x9;
        var f0g0 = f.x0 * (long)g0;
        var f0g1 = f.x0 * (long)g1;
        var f0g2 = f.x0 * (long)g2;
        var f0g3 = f.x0 * (long)g3;
        var f0g4 = f.x0 * (long)g4;
        var f0g5 = f.x0 * (long)g5;
        var f0g6 = f.x0 * (long)g6;
        var f0g7 = f.x0 * (long)g7;
        var f0g8 = f.x0 * (long)g8;
        var f0g9 = f.x0 * (long)g9;
        var f1g0 = f.x1 * (long)g0;
        var f1g1_2 = f1_2 * (long)g1;
        var f1g2 = f.x1 * (long)g2;
        var f1g3_2 = f1_2 * (long)g3;
        var f1g4 = f.x1 * (long)g4;
        var f1g5_2 = f1_2 * (long)g5;
        var f1g6 = f.x1 * (long)g6;
        var f1g7_2 = f1_2 * (long)g7;
        var f1g8 = f.x1 * (long)g8;
        var f1g9_38 = f1_2 * (long)g9_19;
        var f2g0 = f.x2 * (long)g0;
        var f2g1 = f.x2 * (long)g1;
        var f2g2 = f.x2 * (long)g2;
        var f2g3 = f.x2 * (long)g3;
        var f2g4 = f.x2 * (long)g4;
        var f2g5 = f.x2 * (long)g5;
        var f2g6 = f.x2 * (long)g6;
        var f2g7 = f.x2 * (long)g7;
        var f2g8_19 = f.x2 * (long)vec_g19[7]; // g8_19;
        var f2g9_19 = f.x2 * (long)g9_19;
        var f3g0 = f.x3 * (long)g0;
        var f3g1_2 = f3_2 * (long)g1;
        var f3g2 = f.x3 * (long)g2;
        var f3g3_2 = f3_2 * (long)g3;
        var f3g4 = f.x3 * (long)g4;
        var f3g5_2 = f3_2 * (long)g5;
        var f3g6 = f.x3 * (long)g6;
        var f3g7_38 = f3_2 * (long)vec_g19[6]; // g7_19;
        var f3g8_19 = f.x3 * (long)vec_g19[7]; //  g8_19;
        var f3g9_38 = f3_2 * (long)g9_19;
        var f4g0 = f.x4 * (long)g0;
        var f4g1 = f.x4 * (long)g1;
        var f4g2 = f.x4 * (long)g2;
        var f4g3 = f.x4 * (long)g3;
        var f4g4 = f.x4 * (long)g4;
        var f4g5 = f.x4 * (long)g5;
        var f4g6_19 = f.x4 * (long)vec_g19[5]; // g6_19;
        var f4g7_19 = f.x4 * (long)vec_g19[6]; // g7_19;
        var f4g8_19 = f.x4 * (long)vec_g19[7]; // g8_19;
        var f4g9_19 = f.x4 * (long)g9_19;
        var f5g0 = f.x5 * (long)g0;
        var f5g1_2 = f5_2 * (long)g1;
        var f5g2 = f.x5 * (long)g2;
        var f5g3_2 = f5_2 * (long)g3;
        var f5g4 = f.x5 * (long)g4;
        var f5g5_38 = f5_2 * (long)vec_g19[4]; // g5_19;
        var f5g6_19 = f.x5 * (long)vec_g19[5]; // g6_19;
        var f5g7_38 = f5_2 * (long)vec_g19[6]; // g7_19;
        var f5g8_19 = f.x5 * (long)vec_g19[7]; // g8_19;
        var f5g9_38 = f5_2 * (long)g9_19;
        var f6g0 = f.x6 * (long)g0;
        var f6g1 = f.x6 * (long)g1;
        var f6g2 = f.x6 * (long)g2;
        var f6g3 = f.x6 * (long)g3;
        var f6g4_19 = f.x6 * (long)vec_g19[3]; // g4_19;
        var f6g5_19 = f.x6 * (long)vec_g19[4]; // g5_19;
        var f6g6_19 = f.x6 * (long)vec_g19[5]; // g6_19;
        var f6g7_19 = f.x6 * (long)vec_g19[6]; // g7_19;
        var f6g8_19 = f.x6 * (long)vec_g19[7]; // g8_19;
        var f6g9_19 = f.x6 * (long)g9_19;
        var f7g0 = f.x7 * (long)g0;
        var f7g1_2 = f7_2 * (long)g1;
        var f7g2 = f.x7 * (long)g2;
        var f7g3_38 = f7_2 * (long)vec_g19[2]; // g3_19;
        var f7g4_19 = f.x7 * (long)vec_g19[3]; // g4_19;
        var f7g5_38 = f7_2 * (long)vec_g19[4]; // g5_19;
        var f7g6_19 = f.x7 * (long)vec_g19[5]; // g6_19;
        var f7g7_38 = f7_2 * (long)vec_g19[6]; // g7_19;
        var f7g8_19 = f.x7 * (long)vec_g19[7]; // g8_19;
        var f7g9_38 = f7_2 * (long)g9_19;
        var f8g0 = f.x8 * (long)g0;
        var f8g1 = f.x8 * (long)g1;
        var f8g2_19 = f.x8 * (long)vec_g19[1]; // g2_19;
        var f8g3_19 = f.x8 * (long)vec_g19[2]; // g3_19;
        var f8g4_19 = f.x8 * (long)vec_g19[3]; // g4_19;
        var f8g5_19 = f.x8 * (long)vec_g19[4]; // g5_19;
        var f8g6_19 = f.x8 * (long)vec_g19[5]; // g6_19;
        var f8g7_19 = f.x8 * (long)vec_g19[6]; // g7_19;
        var f8g8_19 = f.x8 * (long)vec_g19[7]; // g8_19;
        var f8g9_19 = f.x8 * (long)g9_19;
        var f9g0 = f.x9 * (long)g0;
        var f9g1_38 = f9_2 * (long)vec_g19[0]; // g1_19;
        var f9g2_19 = f.x9 * (long)vec_g19[1]; // g2_19;
        var f9g3_38 = f9_2 * (long)vec_g19[2]; // g3_19;
        var f9g4_19 = f.x9 * (long)vec_g19[3]; // g4_19;
        var f9g5_38 = f9_2 * (long)vec_g19[4]; // g5_19;
        var f9g6_19 = f.x9 * (long)vec_g19[5]; // g6_19;
        var f9g7_38 = f9_2 * (long)vec_g19[6]; // g7_19;
        var f9g8_19 = f.x9 * (long)vec_g19[7]; // g8_19;
        var f9g9_38 = f9_2 * (long)g9_19;
        var h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
        var h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
        var h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
        var h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
        var h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
        var h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
        var h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
        var h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
        var h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
        var h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;

        const long r24 = 1 << 24;
        const long r25 = 1 << 25;

        long carry0 = (h0 + r25) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        long carry4 = (h4 + r25) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        long carry1 = (h1 + r24) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;

        long carry5 = (h5 + r24) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        long carry2 = (h2 + r25) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;

        long carry6 = (h6 + r25) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        long carry3 = (h3 + r24) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;

        long carry7 = (h7 + r24) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        carry4 = (h4 + r25) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        long carry8 = (h8 + r25) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        long carry9 = (h9 + r24) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        carry0 = (h0 + r25) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        h.x0 = (int)h0;
        h.x1 = (int)h1;
        h.x2 = (int)h2;
        h.x3 = (int)h3;
        h.x4 = (int)h4;
        h.x5 = (int)h5;
        h.x6 = (int)h6;
        h.x7 = (int)h7;
        h.x8 = (int)h8;
        h.x9 = (int)h9;
    }
}

[Config(typeof(BenchmarkConfig))]
public class Avx2Benchmark
{
    public Avx2Benchmark()
    {
        var fe0 = new FieldElement(1, 20, 333, -4444, 12345, 6, 7123456, 0, 1231231234, -10);
        Avx2Methods.fe_sq(out var h, ref fe0);
        Avx2Methods.fe_sqB(out var h2, ref fe0);
        // Debug.Assert(h.Equals(h2));

        var fe1 = new FieldElement(2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
        Avx2Methods.fe_mul_original(out h, ref fe0, ref fe1);
        Avx2Methods.fe_mul(out h2, ref fe0, ref fe1);
        Debug.Assert(h.Equals(h2));
    }

    [Params(10)]
    public int Length { get; set; }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    /*[Benchmark]
    public int Add()
    {
        var fe0 = new FieldElement(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        var fe1 = default(FieldElement);
        var x4 = 0;
        for (var i = 0; i < 100; i++)
        {
            Avx2Methods.fe_add(out var h, ref fe0, ref fe1);
            x4 += h.x4;
        }

        return x4;
    }

    [Benchmark]
    public int Add2()
    {
        var fe0 = new FieldElement(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        var fe1 = default(FieldElement);
        var x4 = 0;
        for (var i = 0; i < 100; i++)
        {
            Avx2Methods.fe_add2(out var h, ref fe0, ref fe1);
            x4 += h.x4;
        }

        return x4;
    }

    [Benchmark]
    public int Add3()
    {
        var fe0 = new FieldElement(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        var fe1 = default(FieldElement);
        var x4 = 0;
        for (var i = 0; i < 100; i++)
        {
            Avx2Methods.fe_add3(out var h, ref fe0, ref fe1);
            x4 += h.x4;
        }

        return x4;
    }*/

    /*[Benchmark]
    public int Sq()
    {
        var fe0 = new FieldElement(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        var x4 = 0;
        for (var i = 0; i < 10; i++)
        {
            Avx2Methods.fe_sq(out var h, ref fe0);
            x4 += h.x4;
        }

        return x4;
    }

    [Benchmark]
    public int Sq2()
    {
        var fe0 = new FieldElement(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        var x4 = 0;
        for (var i = 0; i < 10; i++)
        {
            Avx2Methods.fe_sqB(out var h, ref fe0);
            x4 += h.x4;
        }

        return x4;
    }*/

    [Benchmark]
    public int Mul()
    {
        var fe0 = new FieldElement(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        var fe1 = new FieldElement(11, 12, 13, 14, 15, 16, 17, 18, 19, 110);
        var x4 = 0;
        for (var i = 0; i < 10; i++)
        {
            Avx2Methods.fe_mul_original(out var h, ref fe0, ref fe1);
            x4 += h.x4;
        }

        return x4;
    }

    [Benchmark]
    public int Mul2()
    {
        var fe0 = new FieldElement(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        var fe1 = new FieldElement(11, 12, 13, 14, 15, 16, 17, 18, 19, 110);
        var x4 = 0;
        for (var i = 0; i < 10; i++)
        {
            Avx2Methods.fe_mul(out var h, ref fe0, ref fe1);
            x4 += h.x4;
        }

        return x4;
    }
}
