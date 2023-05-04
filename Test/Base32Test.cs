// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Base32Test
{
    [Fact]
    public void Test1()
    {
        this.TestByteArray(new byte[] { });
        this.TestByteArray(new byte[] { 0, });
        this.TestByteArray(new byte[] { 1, });
        this.TestByteArray(new byte[] { 2, });
        this.TestByteArray(new byte[] { 1, 2, });
        this.TestByteArray(new byte[] { 1, 2, 3, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, });
    }

    [Fact]
    public void Test2()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(() => xo.NextUInt64(), x => xo.NextBytes(x));

        for (var i = 0; i < 500; i++)
        {
            var bytes = new byte[i];

            for (var j = 0; j < ((i / 2) + 1); j++)
            {
                rv.NextBytes(bytes);
                this.TestByteArray(bytes);
            }
        }
    }

    private void TestByteArray(byte[] bytes)
    {
        // Byte array to string
        var st = Base32Sort.Reference.FromByteArrayToString(bytes);

        var length = (bytes.Length * 8 / 5) + (((bytes.Length * 8) % 5) == 0 ? 0 : 1);
        st.Length.Is(length);

        // String to byte array
        var b = Base32Sort.Reference.FromStringToByteArray(st);

        bytes.SequenceEqual(b).IsTrue();
    }
}
