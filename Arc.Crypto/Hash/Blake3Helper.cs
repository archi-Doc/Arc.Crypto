// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

public static class Blake3Helper
{
    private const int SizeInBytes = 32;
    private const int LimitPreemptive = 1024;

    public static byte[] Get256_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[SizeInBytes];
        Get256_Span(input, output);
        return output;
    }

    public static (long Hash0, long Hash1, long Hash2, long Hash3) Get256_Long(ReadOnlySpan<byte> input)
    {
        Span<long> hash = stackalloc long[4];
        Get256_Span(input, MemoryMarshal.AsBytes(hash));
        return (hash[0], hash[1], hash[2], hash[3]);
    }

    public static unsafe Struct256 Get256_Struct(ReadOnlySpan<byte> input)
    {
        Struct256 st;
        byte* b = (byte*)&st;
        Get256_Span(input, new(b, Struct256.Length));
        return st;
    }

    public static unsafe void Get256_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != SizeInBytes)
        {
            throw new ArgumentException($"The {nameof(output)} length must be {SizeInBytes} bytes.");
        }

        fixed (void* ptrOut = output, ptr = input)
        {
            var size = input.Length;
            if (size <= LimitPreemptive)
            {
                Blake3Interops.blake3_hash(ptr, (void*)size, ptrOut);
            }
            else
            {
                Blake3Interops.blake3_hash_preemptive(ptr, (void*)size, ptrOut);
            }
        }
    }
}
