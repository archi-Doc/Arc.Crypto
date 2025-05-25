// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class StringLengthTest
{
    [Fact]
    public void TestInt()
    {
        var list = new List<int>();

        var x = 1;
        for (var i = 0; i < 10; i++, x *= 10)
        {
            // x: 1, 10, 100, 1000,,, 1000000000
            list.Add(x - 2);
            list.Add(x - 1);
            list.Add(x);
            list.Add(x + 1);
            list.Add(x + 2);

            list.Add(-x - 2);
            list.Add(-x - 1);
            list.Add(-x);
            list.Add(-x + 1);
            list.Add(-x + 2);
        }

        foreach (var y in list)
        {
            var s = y.ToString();
            s.Length.Is(Arc.BaseHelper.CountDecimalChars(y));
        }
    }

    [Fact]
    public void TestLong()
    {
        var list = new List<long>();

        long x = 1;
        for (var i = 0; i < 19; i++, x *= 10)
        {
            list.Add(x - 2);
            list.Add(x - 1);
            list.Add(x);
            list.Add(x + 1);
            list.Add(x + 2);

            list.Add(-x - 2);
            list.Add(-x - 1);
            list.Add(-x);
            list.Add(-x + 1);
            list.Add(-x + 2);
        }

        foreach (var y in list)
        {
            var s = y.ToString();
            s.Length.Is(Arc.BaseHelper.CountDecimalChars(y));
        }
    }
}
