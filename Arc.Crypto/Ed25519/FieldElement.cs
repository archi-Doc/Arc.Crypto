// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.CompilerServices;

namespace Arc.Crypto.Ed25519;

#pragma warning disable SA1307 // Accessible fields should begin with upper-case letter

internal readonly struct FieldElement
{
    public readonly int x0;
    public readonly int x1;
    public readonly int x2;
    public readonly int x3;
    public readonly int x4;
    public readonly int x5;
    public readonly int x6;
    public readonly int x7;
    public readonly int x8;
    public readonly int x9;

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

    /*[MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FieldElement Add(ref FieldElement a, ref FieldElement b)
    {
        return new(a.x0 + b.x0, a.x1 + b.x1, a.x2 + b.x2, a.x3 + b.x3, a.x4 + b.x4, a.x5 + b.x5, a.x6 + b.x6, a.x7 + b.x7, a.x8 + b.x8, a.x9 + b.x9);
    }*/
}
