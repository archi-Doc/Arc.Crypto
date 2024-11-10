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

        var secretKey = SeedKey.New(KeyOrientation.Signature);
        var st = secretKey.ToString();
        st = secretKey.UnsafeToString();
        SeedKey.TryParse(st, out var secretKey2);
        var result = secretKey.Equals(secretKey2);
    }
}
