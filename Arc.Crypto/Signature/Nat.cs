// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;

namespace Arc.Crypto.EC;

#pragma warning disable SA1405 // Debug.Assert should provide message text

internal abstract class Nat
{
    private const ulong M = 0xFFFFFFFFUL;

    public static uint Add33To(int len, uint x, Span<uint> z)
    {
        ulong c = (ulong)z[0] + x;
        z[0] = (uint)c;
        c >>= 32;
        c += (ulong)z[1] + 1;
        z[1] = (uint)c;
        c >>= 32;
        return c == 0 ? 0 : IncAt(len, z, 2);
    }

    public static uint IncAt(int len, Span<uint> z, int zPos)
    {
        Debug.Assert(zPos <= len);
        for (int i = zPos; i < len; ++i)
        {
            if (++z[i] != uint.MinValue)
            {
                return 0;
            }
        }

        return 1;
    }

    public static uint IncAt(int len, Span<uint> z, int zOff, int zPos)
    {
        Debug.Assert(zPos <= len);
        for (int i = zPos; i < len; ++i)
        {
            if (++z[zOff + i] != uint.MinValue)
            {
                return 0;
            }
        }

        return 1;
    }
}
