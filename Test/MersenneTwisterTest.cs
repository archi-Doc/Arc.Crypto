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
    }
}
