// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

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
