// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;

namespace Sandbox;

internal class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("Sandbox");

        string base32;
        byte[] bytes;

        base32 = Base32Sort.Reference.FromByteArrayToString(new byte[] { });
        bytes = Base32Sort.Reference.FromStringToByteArray(base32);

        base32 = Base32Sort.Table.FromByteArrayToString(new byte[] { 0, });
        bytes = Base32Sort.Table.FromStringToByteArray(base32);

        base32 = Base32Sort.Reference.FromByteArrayToString(new byte[] { 0, 1, 2, 3, 4, 5});
        bytes = Base32Sort.Reference.FromStringToByteArray(base32);
    }
}
