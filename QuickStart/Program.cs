// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously

namespace ConsoleApp1;

internal class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("Quick Start");

        var xo = new Arc.Crypto.Xoshiro256StarStar();
        for (var i = 0; i < 5; i++)
        {
            Console.WriteLine(xo.NextDouble().ToString("F16"));
        }

        var array = new byte[40];
        xo.NextBytes(array);
        Console.WriteLine(BitConverter.ToUInt64(array));
        Console.WriteLine(BitConverter.ToUInt64(array, 8));
        Console.WriteLine(BitConverter.ToUInt64(array, 16));
        Console.WriteLine(BitConverter.ToUInt64(array, 24));
        Console.WriteLine(BitConverter.ToUInt64(array, 32));
        Console.WriteLine();

        QuickStart_RandomVault();
    }

    public static void QuickStart_Xoshiro256StarStar()
    {
        // xoshiro256** is a pseudo-random number generator.
        var xo = new Xoshiro256StarStar(42);
        var ul = xo.NextULong(); // [0, 2^64-1]
        var d = xo.NextDouble(); // [0,1)
        var bytes = new byte[10];
        xo.NextBytes(bytes);
    }

    public static void QuickStart_MersenneTwister()
    {
        // MersenneTwister is a pseudo-random number generator.
        var mt = new MersenneTwister(42);
        var ul = mt.NextULong(); // [0, 2^64-1]
        var d = mt.NextDouble(); // [0,1)
        var bytes = new byte[10];
        mt.NextBytes(bytes);
    }

public static void QuickStart_RandomVault()
{
    // RandomVault is a random number pool.
    // It's thread-safe and faster than lock in most cases.
    var mt = new MersenneTwister(); // Create a random generator.
    var rv = new RandomVault(() => mt.NextULong(), x => mt.NextBytes(x)); // Specify NextULong() or NextBytes() or both delegates, and forget about mt.
    Console.WriteLine("RandomVault:");
    Console.WriteLine(rv.NextLong());
    Console.WriteLine(rv.NextDouble());
}
}
