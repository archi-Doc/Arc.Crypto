// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

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

                // Convert.ToBase64String
                var st = Convert.ToBase64String(bytes);

                // Byte array to string
                var st2 = Base64.Default.FromByteArrayToString(bytes);
                st.Equals(st2).IsTrue();

                // Byte array to utf8
                var utf8 = Base64.Default.FromByteArrayToUtf8(bytes);
                var st3 = Encoding.UTF8.GetString(utf8);
                st.Equals(st3).IsTrue();

                var bytes2 = Base64.Default.FromStringToByteArray(st);
                bytes.SequenceEqual(bytes2).IsTrue();

                var bytes3 = Base64.Default.FromUtf8ToByteArray(utf8);
                bytes.SequenceEqual(bytes3!).IsTrue();

                // Url
                utf8 = Base64.Url.FromByteArrayToUtf8(bytes);
                bytes3 = Base64.Url.FromUtf8ToByteArray(utf8);
                bytes.SequenceEqual(bytes3!).IsTrue();

                st = Base64.Url.FromByteArrayToString(bytes);
                bytes3 = Base64.Url.FromStringToByteArray(st);
                bytes.SequenceEqual(bytes3!).IsTrue();
            }
        }
    }
}
