﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

public static class Base32Sort
{
    public static readonly IBaseConverter Reference = new Base32SortReference();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(int length)
        => ((length << 3) + 4) / 5;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetDecodedLength(int length)
        => (length * 5) >> 3;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FastMod5(int value)
    {
        if (Environment.Is64BitProcess)
        {
            ulong lowbits = ((ulong.MaxValue / 5) + 1) * (uint)value;
            uint highbits = (uint)Math.BigMul(lowbits, 5, out _);
            return (int)highbits;
        }
        else
        {
            return value % 5;
        }
    }
}
