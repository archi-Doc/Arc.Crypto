﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;

namespace Sandbox;

internal class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("Sandbox");

        var id = Id128Helper.Create();
    }
}
