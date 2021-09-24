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

    public static void QuickStart_RandomVault()
    {
        // RandomVault is a random number pool.
        // It's thread-safe and faster than lock in most cases.
        var mt = new MersenneTwister(); // Create a random generator.
        var rv = new RandomVault(() => mt.NextULong(), x => mt.NextBytes(x)); // Specify NextULong() and NextBytes() delegates, and forget about mt.
        Console.WriteLine("RandomVault:");
        Console.WriteLine(rv.NextLong());
        Console.WriteLine(rv.NextDouble());
    }
}
