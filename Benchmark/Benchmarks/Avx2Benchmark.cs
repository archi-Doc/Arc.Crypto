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
        var f0_2 = f0 << 1;
        var f1_2 = f1 << 1;
        var f2_2 = f2 << 1;
        var f3_2 = f3 << 1;
        var f4_2 = f4 << 1;
        var f5_2 = f5 << 1;
        var f6_2 = f6 << 1;
        var f7_2 = f7 << 1;
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
}

[Config(typeof(BenchmarkConfig))]
public class Avx2Benchmark
{
    public Avx2Benchmark()
    {
        var fe0 = new FieldElement(1, 20, 333, -4444, 12345, 6, 7123456, 0, 1231231234, -10);
        Avx2Methods.fe_sq(out var h, ref fe0);
        Avx2Methods.fe_sq2(out var h2, ref fe0);
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

    [Benchmark]
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
            Avx2Methods.fe_sq2(out var h, ref fe0);
            x4 += h.x4;
        }

        return x4;
    }
}
