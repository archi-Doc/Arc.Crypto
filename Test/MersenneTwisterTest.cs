// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class MersenneTwisterTest
{
    [Fact]
    public void Test1()
    {
        var init = new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL };
        var mt = new MersenneTwister(init);

        mt.NextULong().Is(7266447313870364031UL);
        mt.NextULong().Is(4946485549665804864UL);
        mt.NextULong().Is(16945909448695747420UL);
        mt.NextULong().Is(16394063075524226720UL);
        mt.NextULong().Is(4873882236456199058UL);

        for (var i = 0; i < 990; i++)
        {
            mt.NextULong();
        }

        mt.NextULong().Is(10197035660403006684UL);
        mt.NextULong().Is(13004818533162292132UL);
        mt.NextULong().Is(9831652587047067687UL);
        mt.NextULong().Is(7619315254749630976UL);
        mt.NextULong().Is(994412663058993407UL);

        DoubleToString(mt.NextDouble()).Is("0.35252031");
        DoubleToString(mt.NextDouble()).Is("0.51052342");
        DoubleToString(mt.NextDouble()).Is("0.79771733");
        DoubleToString(mt.NextDouble()).Is("0.39300273");
        DoubleToString(mt.NextDouble()).Is("0.27216673");

        string DoubleToString(double d) => d.ToString("F8");
    }
}
