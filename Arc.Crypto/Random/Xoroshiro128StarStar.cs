// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// Represents a pseudo-random number generator based on xoroshiro128**.<br/>
/// This class is NOT thread-safe.<br/>
/// Consider using <see langword="lock"/> statement or <see cref="RandomVault"/> in multi-threaded application.
/// </summary>
public class Xoroshiro128StarStar : RandomUInt64
{
    // xoroshiro128** is based on the algorithm from https://prng.di.unimi.it/xoroshiro128starstar.c:
    //
    // Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)
    //
    // To the extent possible under law, the author has dedicated all copyright
    // and related and neighboring rights to this software to the public domain
    // worldwide.This software is distributed without any warranty.
    //
    // See<http://creativecommons.org/publicdomain/zero/1.0/>.

    public static void InitializeState(ulong seed, out ulong state0, out ulong state1)
    {
        do
        {
            state0 = SplitMix64(ref seed);
            state1 = SplitMix64(ref seed);
        }
        while ((state0 | state1) == 0); // at least one value must be non-zero
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong NextState(ref ulong state0, ref ulong state1)
    {
        var s0 = state0;
        var s1 = state1;

        var result = BitOperations.RotateLeft(s0 * 5, 7) * 9;

        s1 ^= s0;
        state0 = BitOperations.RotateLeft(s0, 24) ^ s1 ^ (s1 << 16);
        state1 = BitOperations.RotateLeft(s1, 37);

        return result;
    }

    private ulong ss0;
    private ulong ss1;

    /// <summary>
    /// Initializes a new instance of the <see cref="Xoroshiro128StarStar"/> class.<br/>
    /// The generator is initialized by random seeds (<see cref="RandomNumberGenerator"/>).
    /// </summary>
    public Xoroshiro128StarStar()
    {
        this.Reset();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Xoroshiro128StarStar"/> class.<br/>
    /// </summary>
    /// <param name="seed">seed.</param>
    public Xoroshiro128StarStar(ulong seed)
    {
        this.Reset(seed);
    }

    /// <summary>
    /// Reset state vectors with random seeds.
    /// </summary>
    public void Reset()
    {
        Span<byte> span = stackalloc byte[2 * sizeof(ulong)];
        var d = MemoryMarshal.Cast<byte, ulong>(span);
        do
        {
            RandomNumberGenerator.Fill(span);
        }
        while ((d[0] | d[1]) == 0); // at least one value must be non-zero.

        this.ss0 = d[0];
        this.ss1 = d[1];
    }

    /// <summary>
    /// Reset state vectors with the specified seed.
    /// </summary>
    /// <param name="seed">seed.</param>
    public void Reset(ulong seed)
    {
        InitializeState(seed, out this.ss0, out this.ss1);
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public override ulong NextUInt64()
    {
        return NextState(ref this.ss0, ref this.ss1);

        /*var s0 = this.ss0;
        var s1 = this.ss1;

        var result = BitOperations.RotateLeft(s0 * 5, 7) * 9;

        s1 ^= s0;
        this.ss0 = BitOperations.RotateLeft(s0, 24) ^ s1 ^ (s1 << 16);
        this.ss1 = BitOperations.RotateLeft(s1, 37);

        return result;*/
    }

    /// <inheritdoc/>
    public override unsafe void NextBytes(Span<byte> buffer)
    {
        var s0 = this.ss0;
        var s1 = this.ss1;

        while (buffer.Length >= sizeof(ulong))
        {
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(buffer), BitOperations.RotateLeft(s0 * 5, 7) * 9);

            s1 ^= s0;
            s0 = BitOperations.RotateLeft(s0, 24) ^ s1 ^ (s1 << 16);
            s1 = BitOperations.RotateLeft(s1, 37);

            buffer = buffer.Slice(sizeof(ulong));
        }

        if (!buffer.IsEmpty)
        {
            var next = BitOperations.RotateLeft(s0 * 5, 7) * 9;
            byte* remainingBytes = (byte*)&next;
            for (var i = 0; i < buffer.Length; i++)
            {
                buffer[i] = remainingBytes[i];
            }

            s1 ^= s0;
            s0 = BitOperations.RotateLeft(s0, 24) ^ s1 ^ (s1 << 16);
            s1 = BitOperations.RotateLeft(s1, 37);
        }

        this.ss0 = s0;
        this.ss1 = s1;
    }
}
