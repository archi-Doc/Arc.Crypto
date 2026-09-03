// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using Arc.Crypto;
using Xunit;

namespace Test;

public class HexTest
{
    [Fact]
    public void TestRoundTrip()
    {
        var random = new Random(42);
        foreach (var length in new[] { 0, 1, 2, 15, 16, 31, 32, 33, 512, 513, 1_000, })
        {
            var source = new byte[length];
            random.NextBytes(source);

            var st = Hex.FromByteArrayToString(source);
            st.Length.Is(length * 2);
            st.Is(Convert.ToHexString(source).ToLowerInvariant()); // Lower-case, no separators, no prefix.
            Hex.FromStringToByteArray(st).SequenceEqual(source).IsTrue();

            // Upper-case input is accepted as well.
            Hex.FromStringToByteArray(st.ToUpperInvariant()).SequenceEqual(source).IsTrue();
        }
    }

    [Fact]
    public void TestOddLength()
    {
        Assert.Throws<ArgumentException>(() => Hex.FromStringToByteArray("abc"));
    }
}
