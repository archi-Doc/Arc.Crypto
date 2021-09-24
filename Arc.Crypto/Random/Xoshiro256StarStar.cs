// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// Represents a pseudo-random number generator based on xoshiro256**.<br/>
/// This class is NOT thread-safe.<br/>
/// Consider using <see langword="lock"/> statement or <see cref="RandomVault"/> in multi-threaded application.
/// </summary>
public class Xoshiro256StarStar : RandomULong
{
    // xoshiro256** is based on the algorithm from http://prng.di.unimi.it/xoshiro256starstar.c:
    //
    //     Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)
    //
    //     To the extent possible under law, the author has dedicated all copyright
    //     and related and neighboring rights to this software to the public domain
    //     worldwide. This software is distributed without any warranty.
    //
    //     See <http://creativecommons.org/publicdomain/zero/1.0/>.

    private ulong ss0;
    private ulong ss1;
    private ulong ss2;
    private ulong ss3;

    /// <summary>
    /// Initializes a new instance of the <see cref="Xoshiro256StarStar"/> class.<br/>
    /// The generator is initialized by random seeds (<see cref="RandomNumberGenerator"/>).
    /// </summary>
    public unsafe Xoshiro256StarStar()
    {
        this.Reset();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Xoshiro256StarStar"/> class.<br/>
    /// </summary>
    /// <param name="seed">seed.</param>
    public Xoshiro256StarStar(ulong seed)
    {
        this.Reset(seed);
    }

    /// <summary>
    /// Reset state vectors with random seeds.
    /// </summary>
    public unsafe void Reset()
    {
        Span<byte> span = stackalloc byte[4 * sizeof(ulong)];
        fixed (byte* b = span)
        {
            ulong* d = (ulong*)b;
            do
            {
                RandomNumberGenerator.Fill(span);
            }
            while ((d[0] | d[1] | d[2] | d[3]) == 0); // at least one value must be non-zero.

            this.ss0 = d[0];
            this.ss1 = d[1];
            this.ss2 = d[2];
            this.ss3 = d[3];
        }
    }

    /// <summary>
    /// Reset state vectors with the specified seed.
    /// </summary>
    /// <param name="seed">seed.</param>
    public void Reset(ulong seed)
    {
        var state = seed;
        do
        {
            this.ss0 = SplitMix64(ref state);
            this.ss1 = SplitMix64(ref state);
            this.ss2 = SplitMix64(ref state);
            this.ss3 = SplitMix64(ref state);
        }
        while ((this.ss0 | this.ss1 | this.ss2 | this.ss3) == 0); // at least one value must be non-zero
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public override ulong NextULong()
    {
        var s0 = this.ss0;
        var s1 = this.ss1;
        var s2 = this.ss2;
        var s3 = this.ss3;

        var result = BitOperations.RotateLeft(s1 * 5, 7) * 9;

        var t = s1 << 17;
        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;
        s2 ^= t;
        s3 = BitOperations.RotateLeft(s3, 45);

        this.ss0 = s0;
        this.ss1 = s1;
        this.ss2 = s2;
        this.ss3 = s3;

        return result;
    }

    /// <inheritdoc/>
    public override unsafe void NextBytes(Span<byte> buffer)
    {
        var s0 = this.ss0;
        var s1 = this.ss1;
        var s2 = this.ss2;
        var s3 = this.ss3;

        while (buffer.Length >= sizeof(ulong))
        {
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(buffer), BitOperations.RotateLeft(s1 * 5, 7) * 9);

            var t = s1 << 17;
            s2 ^= s0;
            s3 ^= s1;
            s1 ^= s2;
            s0 ^= s3;
            s2 ^= t;
            s3 = BitOperations.RotateLeft(s3, 45);

            buffer = buffer.Slice(sizeof(ulong));
        }

        if (!buffer.IsEmpty)
        {
            var next = BitOperations.RotateLeft(s1 * 5, 7) * 9;
            byte* remainingBytes = (byte*)&next;
            for (var i = 0; i < buffer.Length; i++)
            {
                buffer[i] = remainingBytes[i];
            }

            var t = s1 << 17;
            s2 ^= s0;
            s3 ^= s1;
            s1 ^= s2;
            s0 ^= s3;
            s2 ^= t;
            s3 = BitOperations.RotateLeft(s3, 45);
        }

        this.ss0 = s0;
        this.ss1 = s1;
        this.ss2 = s2;
        this.ss3 = s3;
    }
}
