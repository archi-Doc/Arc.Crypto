// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// Provides methods for computing BLAKE3 hashes.
/// </summary>
/// <remarks>
/// This class includes methods for computing 256-bit BLAKE3 hashes.
/// The hash can be returned in various formats including byte arrays, tuples of longs, and custom structs.
/// </remarks>
public static class Blake3
{
    public const int Size = 32;
    internal const int LimitPreemptive = 1024;

    /// <summary>
    /// Computes the BLAKE3 hash of the input data and returns the hash as a byte array.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <returns>A 32-byte array containing the BLAKE3 hash.</returns>
    public static byte[] Get256_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[Size];
        Get256_Span(input, output);
        return output;
    }

    /// <summary>
    /// Computes the BLAKE3 hash of the input data and returns the hash as a tuple of four long values.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <returns>A tuple containing four long values representing the BLAKE3 hash.</returns>
    public static (long Hash0, long Hash1, long Hash2, long Hash3) Get256_Long(ReadOnlySpan<byte> input)
    {
        Span<long> hash = stackalloc long[4];
        Get256_Span(input, MemoryMarshal.AsBytes(hash));
        return (hash[0], hash[1], hash[2], hash[3]);
    }

    /// <summary>
    /// Computes the BLAKE3 hash of the input data and returns the hash as a Struct256.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <returns>A Struct256 containing the BLAKE3 hash.</returns>
    public static unsafe Struct256 Get256_Struct(ReadOnlySpan<byte> input)
    {
        Struct256 st;
        byte* b = (byte*)&st;
        Get256_Span(input, new(b, Struct256.Length));
        return st;
    }

    /// <summary>
    /// Computes the BLAKE3 hash of the input data and writes the hash to the output span.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <param name="output">The span to write the 32-byte BLAKE3 hash to.</param>
    /// <exception cref="ArgumentException">Thrown when the output span length is not 32 bytes.</exception>
    public static unsafe void Get256_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != Size)
        {
            throw new ArgumentException($"The {nameof(output)} length must be {Size} bytes.");
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
