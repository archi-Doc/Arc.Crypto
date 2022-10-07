// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access

namespace Test;

public class Base64Test
{
    [Fact]
    public void Test1()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(() => xo.NextUInt64(), x => xo.NextBytes(x));

        for (var i = 0; i < 500; i++)
        {
            var bytes = new byte[i];

            for (var j = 0; j < ((i / 2) + 1); j++)
            {
                rv.NextBytes(bytes);

                var utf = Base64.EncodeToBase64Utf8(bytes);
                var utf2 = Base64b.FromByteArrayToUtf8(bytes);
                utf.SequenceEqual(utf2).IsTrue();

                var st = Base64.EncodeToBase64Utf16(bytes);
                var st2 = Base64b.FromByteArrayToString(bytes);
                st.Equals(st2).IsTrue();

                Convert.ToBase64String(bytes).Equals(st2).IsTrue();
            }
        }
    }
}
