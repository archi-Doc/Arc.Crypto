// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Xoroshiro128StarStarTest
{
    private const int Length = 1023;
    private const int Length2 = 1024;

    [Fact]
    public void Test1()
    {
        var xo = new Xoroshiro128StarStar(43);
        var bytes = new byte[Length];
        xo.NextBytes(bytes);

        xo.Reset(43);
        var bytes2 = new byte[Length2];
        var ulongs = MemoryMarshal.Cast<byte, ulong>(bytes2);
        for (var i = 0; i < Length2 / sizeof(ulong); i++)
        {
            ulongs[i] = xo.NextUInt64();
        }

        bytes.AsSpan().SequenceEqual(bytes2.AsSpan(0, Length)).IsTrue();
    }
}
