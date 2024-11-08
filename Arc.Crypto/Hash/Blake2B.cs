// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// Provides methods for computing BLAKE2B hashes.
/// </summary>
/// <remarks>
/// This class includes methods for computing 256-bit and 512-bit BLAKE2B hashes.
/// The hash can be returned in various formats including byte arrays, tuples of longs, and custom structs.
/// </remarks>
public static class Blake2B
{
    private const int Hash256Size = 32;
    private const int Hash512Size = 64;

    /// <summary>
    /// Computes a 256-bit BLAKE2B hash of the input data and returns it as a byte array.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <returns>A 256-bit hash as a byte array.</returns>
    public static byte[] Get256_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[Hash256Size];
        Get256_Span(input, output);
        return output;
    }

    /// <summary>
    /// Computes a 256-bit BLAKE2B hash of the input data and returns it as a tuple of longs.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <returns>A tuple containing the 256-bit hash as four longs.</returns>
    public static (long Hash0, long Hash1, long Hash2, long Hash3) Get256_Long(ReadOnlySpan<byte> input)
    {
        Span<long> hash = stackalloc long[4];
        Get256_Span(input, MemoryMarshal.AsBytes(hash));
        return (hash[0], hash[1], hash[2], hash[3]);
    }

    /// <summary>
    /// Computes a 256-bit BLAKE2B hash of the input data and returns it as a Struct256.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <returns>A Struct256 containing the 256-bit hash.</returns>
    public static unsafe Struct256 Get256_Struct(ReadOnlySpan<byte> input)
    {
        Struct256 st;
        byte* b = (byte*)&st;
        Get256_Span(input, new(b, Struct256.Length));
        return st;
    }

    /// <summary>
    /// Computes a 256-bit BLAKE2B hash of the input data and writes it to the output span.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <param name="output">The span to write the 256-bit hash to.</param>
    /// <exception cref="ArgumentException">Thrown when the output span length is not 32 bytes.</exception>
    public static void Get256_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != Hash256Size)
        {
            throw new ArgumentException($"The {nameof(output)} length must be {Hash256Size} bytes.");
        }

        int result;
        result = LibsodiumInterops.crypto_generichash_blake2b(output, Hash256Size, input, (ulong)input.Length, IntPtr.Zero, 0);
    }

    /// <summary>
    /// Computes a 512-bit BLAKE2B hash of the input data and returns it as a byte array.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <returns>A 512-bit hash as a byte array.</returns>
    public static byte[] Get512_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[Hash512Size];
        Get512_Span(input, output);
        return output;
    }

    /// <summary>
    /// Computes a 512-bit BLAKE2B hash of the input data and writes it to the output span.
    /// </summary>
    /// <param name="input">The input data to hash.</param>
    /// <param name="output">The span to write the 512-bit hash to.</param>
    /// <exception cref="ArgumentException">Thrown when the output span length is not 64 bytes.</exception>
    public static void Get512_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != Hash512Size)
        {
            throw new ArgumentException($"The {nameof(output)} length must be {Hash512Size} bytes.");
        }

        int result;
        result = LibsodiumInterops.crypto_generichash_blake2b(output, Hash512Size, input, (ulong)input.Length, IntPtr.Zero, 0);
    }
}
