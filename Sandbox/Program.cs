// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics;
using System;
using Arc.Crypto;
using System.Runtime.Intrinsics;

namespace Sandbox;

internal class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("Sandbox");

        if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            var value = Vector128.Create(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
            // var value = Vector128.Create(new byte[] { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15 });
            var roundKey = Vector128.Create(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
            var result = System.Runtime.Intrinsics.X86.Aes.Encrypt(value, roundKey);

            Console.WriteLine("X86");
            Console.WriteLine(value);
            Console.WriteLine(roundKey);
            Console.WriteLine(result);
        }

        if (System.Runtime.Intrinsics.Arm.Aes.Arm64.IsSupported)
        {
            var a = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
            var value = Vector128.Create(a.ToArray());
            var roundKey = Vector128.Create(a.ToArray());
            var result = System.Runtime.Intrinsics.Arm.Aes.Encrypt(value, roundKey);
            // result = System.Runtime.Intrinsics.Arm.Aes.InverseMixColumns(result);

            Console.WriteLine("Arm");
            Console.WriteLine(value);
            Console.WriteLine(roundKey);
            Console.WriteLine(result);
        }
    }
}
