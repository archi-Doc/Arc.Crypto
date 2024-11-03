// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto.Ed25519;

#pragma warning disable SA1307 // Accessible fields should begin with upper-case letter

internal struct FieldElement
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
}
