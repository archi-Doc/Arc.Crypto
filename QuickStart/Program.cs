// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

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
    }
}
