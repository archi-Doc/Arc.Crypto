// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using Arc.Crypto;
using Xunit;

namespace Test;

public class HashtableTest
{
    [Fact]
    public void Test1()
    {
        var array = Enumerable.Range(0, 16).ToArray();

        var hashtable = new UInt32Hashtable<int>();
        foreach (var x in array)
        {
            hashtable.TryAdd((uint)x, x);
        }

        hashtable.TryAdd(1, 3);

        var r = hashtable.ToArray();
        r.SequenceEqual(array).IsTrue();

        hashtable.Count.Is(array.Length);

        hashtable.TryGetValue(4, out _).IsTrue();
        hashtable.TryGetValue(24, out _).IsFalse();
    }
}
