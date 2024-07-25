// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#pragma warning disable SA1201 // Elements should appear in the correct order
#pragma warning disable SA1307 // Accessible fields should begin with upper-case letter
#pragma warning disable SA1310 // Field names should not contain underscore
#pragma warning disable SA1402 // File may only contain a single type

namespace Arc.Crypto;

/// <summary>
/// xxHash 64bit Class.
/// </summary>
public unsafe partial class XxHash64 : InternalXXHash, IHash
{
    /// <summary>
    /// Length of the hash in bytes.
    /// </summary>
    public const int HashLength = 8;

    private const ulong PRIME64_1 = 11400714785074694791ul;
    private const ulong PRIME64_2 = 14029467366897019727ul;
    private const ulong PRIME64_3 = 1609587929392839161ul;
    private const ulong PRIME64_4 = 9650029242287828579ul;
    private const ulong PRIME64_5 = 2870177450012600261ul;

    private XXH64_state state;

    /// <inheritdoc/>
    public string HashName => "xxHash64";

    /// <inheritdoc/>
    public uint HashBits => 64;

    /// <inheritdoc/>
    public bool IsCryptographic => false;

    /// <summary>
    /// Static function: Calculates a 64bit hash from the given data.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A 64bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe ulong Hash64(ReadOnlySpan<byte> input)
    {
        fixed (void* p = input)
        {
            return XXH64_hash(p, input.Length, 0);
        }
    }

    /// <summary>
    /// Static function: Calculates a 64bit hash from the given string.
    /// </summary>
    /// <param name="str">The string containing the characters to calculates.</param>
    /// <returns>A 64bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe ulong Hash64(string str) => Hash64(MemoryMarshal.Cast<char, byte>(str));

    /// <inheritdoc/>
    public byte[] GetHash(ReadOnlySpan<byte> input) => BitConverter.GetBytes(Hash64(input));

    /// <inheritdoc/>
    public byte[] GetHash(byte[] input, int inputOffset, int inputCount) => BitConverter.GetBytes(Hash64(input.AsSpan(inputOffset, inputCount)));

    /// <inheritdoc/>
    public void HashInitialize()
    {
        fixed (XXH64_state* state = &this.state)
        {
            XXH64_reset(state, 0);
        }
    }

    /// <inheritdoc/>
    public void HashUpdate(ReadOnlySpan<byte> input)
    {
        fixed (void* p = input)
        {
            fixed (XXH64_state* state = &this.state)
            {
                XXH64_update(state, p, input.Length);
            }
        }
    }

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount) => this.HashUpdate(input.AsSpan(inputOffset, inputCount));

    /// <inheritdoc/>
    public byte[] HashFinal()
    {
        fixed (XXH64_state* state = &this.state)
        {
            return BitConverter.GetBytes(XXH64_digest(state));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct XXH64_state
    {
        public ulong total_len;
        public ulong v1;
        public ulong v2;
        public ulong v3;
        public ulong v4;
        public fixed ulong mem64[4];
        public uint memsize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong XXH_rotl64(ulong x, int r) => (x << r) | (x >> (64 - r));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong XXH64_round(ulong acc, ulong input) =>
        XXH_rotl64(acc + (input * PRIME64_2), 31) * PRIME64_1;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong XXH64_mergeRound(ulong acc, ulong val) =>
        ((acc ^ XXH64_round(0, val)) * PRIME64_1) + PRIME64_4;

    private static ulong XXH64_hash(void* input, int len, ulong seed)
    {
        var p = (byte*)input;
        var bEnd = p + len;
        ulong h64;

        if (len >= 32)
        {
            var limit = bEnd - 32;
            var v1 = seed + PRIME64_1 + PRIME64_2;
            var v2 = seed + PRIME64_2;
            var v3 = seed + 0;
            var v4 = seed - PRIME64_1;

            do
            {
                v1 = XXH64_round(v1, XXH_read64(p + 0));
                v2 = XXH64_round(v2, XXH_read64(p + 8));
                v3 = XXH64_round(v3, XXH_read64(p + 16));
                v4 = XXH64_round(v4, XXH_read64(p + 24));
                p += 32;
            }
            while (p <= limit);

            h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);
            h64 = XXH64_mergeRound(h64, v1);
            h64 = XXH64_mergeRound(h64, v2);
            h64 = XXH64_mergeRound(h64, v3);
            h64 = XXH64_mergeRound(h64, v4);
        }
        else
        {
            h64 = seed + PRIME64_5;
        }

        h64 += (ulong)len;

        while (p + 8 <= bEnd)
        {
            h64 ^= XXH64_round(0, XXH_read64(p));
            h64 = (XXH_rotl64(h64, 27) * PRIME64_1) + PRIME64_4;
            p += 8;
        }

        if (p + 4 <= bEnd)
        {
            h64 ^= XXH_read32(p) * PRIME64_1;
            h64 = (XXH_rotl64(h64, 23) * PRIME64_2) + PRIME64_3;
            p += 4;
        }

        while (p < bEnd)
        {
            h64 ^= (*p) * PRIME64_5;
            h64 = XXH_rotl64(h64, 11) * PRIME64_1;
            p++;
        }

        h64 ^= h64 >> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >> 29;
        h64 *= PRIME64_3;
        h64 ^= h64 >> 32;

        return h64;
    }

    private static void XXH64_reset(XXH64_state* state, ulong seed)
    {
        XXH_zero(state, sizeof(XXH64_state));
        state->v1 = seed + PRIME64_1 + PRIME64_2;
        state->v2 = seed + PRIME64_2;
        state->v3 = seed + 0;
        state->v4 = seed - PRIME64_1;
    }

    private static void XXH64_update(XXH64_state* state, void* input, int len)
    {
        var p = (byte*)input;
        var bEnd = p + len;

        state->total_len += (ulong)len;

        if (state->memsize + len < 32)
        {
            /* fill in tmp buffer */
            XXH_copy((byte*)state->mem64 + state->memsize, input, len);
            state->memsize += (uint)len;
            return;
        }

        if (state->memsize > 0)
        {
            /* tmp buffer is full */
            XXH_copy((byte*)state->mem64 + state->memsize, input, (int)(32 - state->memsize));
            state->v1 = XXH64_round(state->v1, XXH_read64(state->mem64 + 0));
            state->v2 = XXH64_round(state->v2, XXH_read64(state->mem64 + 1));
            state->v3 = XXH64_round(state->v3, XXH_read64(state->mem64 + 2));
            state->v4 = XXH64_round(state->v4, XXH_read64(state->mem64 + 3));
            p += 32 - state->memsize;
            state->memsize = 0;
        }

        if (p + 32 <= bEnd)
        {
            var limit = bEnd - 32;
            var v1 = state->v1;
            var v2 = state->v2;
            var v3 = state->v3;
            var v4 = state->v4;

            do
            {
                v1 = XXH64_round(v1, XXH_read64(p + 0));
                v2 = XXH64_round(v2, XXH_read64(p + 8));
                v3 = XXH64_round(v3, XXH_read64(p + 16));
                v4 = XXH64_round(v4, XXH_read64(p + 24));
                p += 32;
            }
            while (p <= limit);

            state->v1 = v1;
            state->v2 = v2;
            state->v3 = v3;
            state->v4 = v4;
        }

        if (p < bEnd)
        {
            XXH_copy(state->mem64, p, (int)(bEnd - p));
            state->memsize = (uint)(bEnd - p);
        }
    }

    private static ulong XXH64_digest(XXH64_state* state)
    {
        var p = (byte*)state->mem64;
        var bEnd = (byte*)state->mem64 + state->memsize;
        ulong h64;

        if (state->total_len >= 32)
        {
            var v1 = state->v1;
            var v2 = state->v2;
            var v3 = state->v3;
            var v4 = state->v4;

            h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);
            h64 = XXH64_mergeRound(h64, v1);
            h64 = XXH64_mergeRound(h64, v2);
            h64 = XXH64_mergeRound(h64, v3);
            h64 = XXH64_mergeRound(h64, v4);
        }
        else
        {
            h64 = state->v3 + PRIME64_5;
        }

        h64 += (ulong)state->total_len;

        while (p + 8 <= bEnd)
        {
            h64 ^= XXH64_round(0, XXH_read64(p));
            h64 = (XXH_rotl64(h64, 27) * PRIME64_1) + PRIME64_4;
            p += 8;
        }

        if (p + 4 <= bEnd)
        {
            h64 ^= XXH_read32(p) * PRIME64_1;
            h64 = (XXH_rotl64(h64, 23) * PRIME64_2) + PRIME64_3;
            p += 4;
        }

        while (p < bEnd)
        {
            h64 ^= *p * PRIME64_5;
            h64 = XXH_rotl64(h64, 11) * PRIME64_1;
            p++;
        }

        h64 ^= h64 >> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >> 29;
        h64 *= PRIME64_3;
        h64 ^= h64 >> 32;

        return h64;
    }
}

/// <summary>
/// xxHash 32bit Class.
/// </summary>
public unsafe class XXHash32 : InternalXXHash, IHash
{
    private const uint PRIME32_1 = 2654435761u;
    private const uint PRIME32_2 = 2246822519u;
    private const uint PRIME32_3 = 3266489917u;
    private const uint PRIME32_4 = 668265263u;
    private const uint PRIME32_5 = 374761393u;

    private XXH32_state state;

    /// <inheritdoc/>
    public string HashName => "xxHash32";

    /// <inheritdoc/>
    public uint HashBits => 32;

    /// <inheritdoc/>
    public bool IsCryptographic => false;

    /// <summary>
    /// Static function: Calculates a 32bit hash from the given data.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A 32bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe uint Hash32(ReadOnlySpan<byte> input)
    {
        fixed (void* p = input)
        {
            return XXH32_hash(p, input.Length, 0);
        }
    }

    /// <summary>
    /// Static function: Calculates a 32bit hash from the given string.
    /// </summary>
    /// <param name="str">The string containing the characters to calculates.</param>
    /// <returns>A 32bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe uint Hash32(string str) => Hash32(MemoryMarshal.Cast<char, byte>(str));

    /// <inheritdoc/>
    public byte[] GetHash(ReadOnlySpan<byte> input) => BitConverter.GetBytes(Hash32(input));

    /// <inheritdoc/>
    public byte[] GetHash(byte[] input, int inputOffset, int inputCount) => BitConverter.GetBytes(Hash32(input.AsSpan(inputOffset, inputCount)));

    /// <inheritdoc/>
    public void HashInitialize()
    {
        fixed (XXH32_state* state = &this.state)
        {
            XXH32_reset(state, 0);
        }
    }

    /// <inheritdoc/>
    public void HashUpdate(ReadOnlySpan<byte> input)
    {
        fixed (void* p = input)
        {
            fixed (XXH32_state* state = &this.state)
            {
                XXH32_update(state, p, input.Length);
            }
        }
    }

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount) => this.HashUpdate(input.AsSpan(inputOffset, inputCount));

    /// <inheritdoc/>
    public byte[] HashFinal()
    {
        fixed (XXH32_state* state = &this.state)
        {
            return BitConverter.GetBytes(XXH32_digest(state));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct XXH32_state
    {
        public uint total_len_32;
        public bool large_len;
        public uint v1;
        public uint v2;
        public uint v3;
        public uint v4;
        public fixed uint mem32[4];
        public uint memsize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint XXH32_rotl(uint x, int r) => (x << r) | (x >> (32 - r));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint XXH32_round(uint seed, uint input) =>
        XXH32_rotl(seed + (input * PRIME32_2), 13) * PRIME32_1;

    private static uint XXH32_hash(void* input, int len, uint seed)
    {
        var p = (byte*)input;
        var bEnd = p + len;
        uint h32;

        if (len >= 16)
        {
            var limit = bEnd - 16;
            var v1 = seed + PRIME32_1 + PRIME32_2;
            var v2 = seed + PRIME32_2;
            var v3 = seed + 0;
            var v4 = seed - PRIME32_1;

            do
            {
                v1 = XXH32_round(v1, XXH_read32(p + 0));
                v2 = XXH32_round(v2, XXH_read32(p + 4));
                v3 = XXH32_round(v3, XXH_read32(p + 8));
                v4 = XXH32_round(v4, XXH_read32(p + 12));
                p += 16;
            }
            while (p <= limit);

            h32 = XXH32_rotl(v1, 1) + XXH32_rotl(v2, 7) + XXH32_rotl(v3, 12) + XXH32_rotl(v4, 18);
        }
        else
        {
            h32 = seed + PRIME32_5;
        }

        h32 += (uint)len;

        while (p + 4 <= bEnd)
        {
            h32 = XXH32_rotl(h32 + (XXH_read32(p) * PRIME32_3), 17) * PRIME32_4;
            p += 4;
        }

        while (p < bEnd)
        {
            h32 = XXH32_rotl(h32 + (*p * PRIME32_5), 11) * PRIME32_1;
            p++;
        }

        h32 ^= h32 >> 15;
        h32 *= PRIME32_2;
        h32 ^= h32 >> 13;
        h32 *= PRIME32_3;
        h32 ^= h32 >> 16;

        return h32;
    }

    private static void XXH32_reset(XXH32_state* state, uint seed)
    {
        XXH_zero(state, sizeof(XXH32_state));
        state->v1 = seed + PRIME32_1 + PRIME32_2;
        state->v2 = seed + PRIME32_2;
        state->v3 = seed + 0;
        state->v4 = seed - PRIME32_1;
    }

    private static void XXH32_update(XXH32_state* state, void* input, int len)
    {
        var p = (byte*)input;
        var bEnd = p + len;

        state->total_len_32 += (uint)len;
        state->large_len |= len >= 16 || state->total_len_32 >= 16;

        if (state->memsize + len < 16)
        {
            /* fill in tmp buffer */
            XXH_copy((byte*)state->mem32 + state->memsize, input, len);
            state->memsize += (uint)len;
            return;
        }

        if (state->memsize > 0)
        {
            /* some data left from previous update */
            XXH_copy((byte*)state->mem32 + state->memsize, input, (int)(16 - state->memsize));
            var p32 = state->mem32;
            state->v1 = XXH32_round(state->v1, XXH_read32(p32 + 0));
            state->v2 = XXH32_round(state->v2, XXH_read32(p32 + 1));
            state->v3 = XXH32_round(state->v3, XXH_read32(p32 + 2));
            state->v4 = XXH32_round(state->v4, XXH_read32(p32 + 3));
            p += 16 - state->memsize;
            state->memsize = 0;
        }

        if (p <= bEnd - 16)
        {
            var limit = bEnd - 16;
            var v1 = state->v1;
            var v2 = state->v2;
            var v3 = state->v3;
            var v4 = state->v4;

            do
            {
                v1 = XXH32_round(v1, XXH_read32(p + 0));
                v2 = XXH32_round(v2, XXH_read32(p + 4));
                v3 = XXH32_round(v3, XXH_read32(p + 8));
                v4 = XXH32_round(v4, XXH_read32(p + 12));
                p += 16;
            }
            while (p <= limit);

            state->v1 = v1;
            state->v2 = v2;
            state->v3 = v3;
            state->v4 = v4;
        }

        if (p < bEnd)
        {
            XXH_copy(state->mem32, p, (int)(bEnd - p));
            state->memsize = (uint)(bEnd - p);
        }
    }

    private static uint XXH32_digest(XXH32_state* state)
    {
        var p = (byte*)state->mem32;
        var bEnd = (byte*)state->mem32 + state->memsize;
        uint h32;

        if (state->large_len)
        {
            h32 = XXH32_rotl(state->v1, 1)
                + XXH32_rotl(state->v2, 7)
                + XXH32_rotl(state->v3, 12)
                + XXH32_rotl(state->v4, 18);
        }
        else
        {
            h32 = state->v3 + PRIME32_5;
        }

        h32 += state->total_len_32;

        while (p + 4 <= bEnd)
        {
            h32 += XXH_read32(p) * PRIME32_3;
            h32 = XXH32_rotl(h32, 17) * PRIME32_4;
            p += 4;
        }

        while (p < bEnd)
        {
            h32 += (*p) * PRIME32_5;
            h32 = XXH32_rotl(h32, 11) * PRIME32_1;
            p++;
        }

        h32 ^= h32 >> 15;
        h32 *= PRIME32_2;
        h32 ^= h32 >> 13;
        h32 *= PRIME32_3;
        h32 ^= h32 >> 16;

        return h32;
    }
}

/// <summary>
/// Base class for xxHash 32/64 bit. Do not use directly.
/// </summary>
public unsafe class InternalXXHash
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InternalXXHash"/> class. Protected constructor to prevent instantiation.
    /// </summary>
    protected InternalXXHash()
    {
    }

    /// <summary>
    /// Converts (void*) to (uint*).
    /// </summary>
    /// <param name="p">pointer void*.</param>
    /// <returns>pointer uint*.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint XXH_read32(void* p) => *(uint*)p;

    /// <summary>
    /// Convert (void*) to (ulong*).
    /// </summary>
    /// <param name="p">pointer void*.</param>
    /// <returns>pointer ulong*.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong XXH_read64(void* p) => *(ulong*)p;

    /// <summary>
    /// Fills target with zeros.
    /// </summary>
    /// <param name="target">target data.</param>
    /// <param name="length">target length.</param>
    internal static void XXH_zero(void* target, int length)
    {
        var targetP = (byte*)target;

        while (length >= sizeof(ulong))
        {
            *(ulong*)targetP = 0;
            targetP += sizeof(ulong);
            length -= sizeof(ulong);
        }

        if (length >= sizeof(uint))
        {
            *(uint*)targetP = 0;
            targetP += sizeof(uint);
            length -= sizeof(uint);
        }

        if (length >= sizeof(ushort))
        {
            *(ushort*)targetP = 0;
            targetP += sizeof(ushort);
            length -= sizeof(ushort);
        }

        if (length > 0)
        {
            *targetP = 0;
        }
    }

    /// <summary>
    /// Copy buffer.
    /// </summary>
    /// <param name="target">target buffer.</param>
    /// <param name="source">source buffer.</param>
    /// <param name="length">data length.</param>
    internal static void XXH_copy(void* target, void* source, int length)
    {
        var sourceP = (byte*)source;
        var targetP = (byte*)target;

        while (length >= sizeof(ulong))
        {
            *(ulong*)targetP = *(ulong*)sourceP;
            targetP += sizeof(ulong);
            sourceP += sizeof(ulong);
            length -= sizeof(ulong);
        }

        if (length >= sizeof(uint))
        {
            *(uint*)targetP = *(uint*)sourceP;
            targetP += sizeof(uint);
            sourceP += sizeof(uint);
            length -= sizeof(uint);
        }

        if (length >= sizeof(ushort))
        {
            *(ushort*)targetP = *(ushort*)sourceP;
            targetP += sizeof(ushort);
            sourceP += sizeof(ushort);
            length -= sizeof(ushort);
        }

        if (length > 0)
        {
            *targetP = *sourceP;
        }
    }
}
