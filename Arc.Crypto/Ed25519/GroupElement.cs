// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto.Ed25519;

#pragma warning disable SA1307 // Accessible fields should begin with upper-case letter

internal struct GroupElementP2
{
    public FieldElement X;
    public FieldElement Y;
    public FieldElement Z;

    public GroupElementP2(ref GroupElementP3 p3)
    {
        this.X = p3.X;
        this.Y = p3.Y;
        this.Z = p3.Z;
    }
}

internal struct GroupElementP3
{
    public FieldElement X;
    public FieldElement Y;
    public FieldElement Z;
    public FieldElement T;
}

internal struct GroupElementP1P1
{
    public FieldElement X;
    public FieldElement Y;
    public FieldElement Z;
    public FieldElement T;
}

internal struct GroupElementPreComp
{
    public FieldElement yplusx;
    public FieldElement yminusx;
    public FieldElement xy2d;

    public GroupElementPreComp(FieldElement yplusx, FieldElement yminusx, FieldElement xy2d)
    {
        this.yplusx = yplusx;
        this.yminusx = yminusx;
        this.xy2d = xy2d;
    }
}

/*internal struct GroupElementCached
{
    public FieldElement YplusX;
    public FieldElement YminusX;
    public FieldElement Z;
    public FieldElement T2d;
}*/
