// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics;
using System;
using Arc.Crypto;

namespace Sandbox;

internal class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("Sandbox");

        var secretKey = SeedKey.New();
        var st = secretKey.ToString();
        st = secretKey.UnsafeToString();
        SeedKey.TryParse(st, out var secretKey2);
    }
}
