// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Xoshiro256StarStarTest
{
    [Fact]
    public void QuickStart_Xoshiro256StarStar()
    {
        // xoshiro256** is a pseudo-random number generator.
        var xo = new Xoshiro256StarStar(42);
        var ul = xo.NextULong(); // [0, 2^64-1]
        var d = xo.NextDouble(); // [0,1)
        var bytes = new byte[10];
        xo.NextBytes(bytes);
    }

    [Fact]
    public void Test1()
    {
        // SplitMix64
        var seed = 1234567ul;
        Xoshiro256StarStar.SplitMix64(ref seed).Is(6457827717110365317ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(3203168211198807973ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(9817491932198370423ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(4593380528125082431ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(16408922859458223821ul);
    }
}
