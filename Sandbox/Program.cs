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

        var message = new byte[] { 0, 1, 2, 3, };
        Ed25519Helper.KeyPairFromSeed(Sha3Helper.Get256_ByteArray([]), out var pub2, out var pri2);
        var signature = new byte[Ed25519Helper.SignatureSizeInBytes];
        Ed25519Helper.Sign(message, pri2, signature);

        for (var i = 0; i < 100_000; i++)
        {
            Ed25519Helper.Verify(message, pub2, signature);
        }
    }
}
