﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

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

        var xo = new Xoshiro256StarStar(42);
        DoubleToString(xo.NextDouble()).Is("0.0838629710598822");
        DoubleToString(xo.NextDouble()).Is("0.3789802506626686");
        DoubleToString(xo.NextDouble()).Is("0.6800434110281394");
        DoubleToString(xo.NextDouble()).Is("0.9246929453253876");
        DoubleToString(xo.NextDouble()).Is("0.9918039142821028");

        string DoubleToString(double d) => d.ToString("F16");

        xo.NextULong().Is(14199186830065750584ul);
        xo.NextULong().Is(13267978908934200754ul);
        xo.NextULong().Is(15679888225317814407ul);
        xo.NextULong().Is(14044878350692344958ul);
        xo.NextULong().Is(10760895422300929085ul);
    }
}
