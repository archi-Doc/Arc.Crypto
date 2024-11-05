// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Arc.Crypto;

public static class Blake2BHelper
{
    private const int Hash256SizeInBytes = 32;
    private const int Hash384SizeInBytes = 48;
    private const int Hash512SizeInBytes = 64;

    public static byte[] Get256_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[Hash256SizeInBytes];
        Get256_Span(input, output);
        return output;
    }

    public static void Get256_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != Hash256SizeInBytes)
        {
            throw new ArgumentException($"The {nameof(output)} length must be {Hash256SizeInBytes} bytes.");
        }

        int result;
        result = LibsodiumInterops.crypto_generichash_blake2b(output, Hash256SizeInBytes, input, (ulong)input.Length, IntPtr.Zero, 0);
    }

    public static byte[] Get512_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[Hash512SizeInBytes];
        Get512_Span(input, output);
        return output;
    }

    public static void Get512_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != Hash512SizeInBytes)
        {
            throw new ArgumentException($"The {nameof(output)} length must be {Hash512SizeInBytes} bytes.");
        }

        int result;
        result = LibsodiumInterops.crypto_generichash_blake2b(output, Hash512SizeInBytes, input, (ulong)input.Length, IntPtr.Zero, 0);
    }
}
