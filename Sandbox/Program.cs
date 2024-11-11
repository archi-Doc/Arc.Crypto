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

        Span<byte> plaintext = [0, 1, 10, 100];
        var ciphertext = PasswordEncryption.Encrypt(plaintext, "pass");
        PasswordEncryption.TryDecrypt(ciphertext, "pass", out var data);

        var seedKey = SeedKey.New(KeyOrientation.Signature);
        var st = seedKey.ToString();
        st = seedKey.UnsafeToString();
        SeedKey.TryParse(st, out var seedKey2);
        var result = seedKey.Equals(seedKey2);

        seedKey = SeedKey.New(KeyOrientation.Encryption);
        st = seedKey.ToString();
        st = seedKey.UnsafeToString();
        SeedKey.TryParse(st, out seedKey2);
        result = seedKey.Equals(seedKey2);
    }
}
