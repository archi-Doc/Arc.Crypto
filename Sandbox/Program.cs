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

        var secretKey = Ed25519SecretKey.New();
        var st = secretKey.ToString();
        st = secretKey.UnsafeToString();
        Ed25519SecretKey.TryParse(st, out var secretKey2);
    }
}
