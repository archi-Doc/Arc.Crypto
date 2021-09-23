// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

public class Xoshiro256StarStar
{
    // NextULong is based on the algorithm from http://prng.di.unimi.it/xoshiro256starstar.c:
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int Log2Ceiling(ulong value)
    {
        var result = BitOperations.Log2(value);
        if (BitOperations.PopCount(value) != 1)
        {
            result++;
        }

        return result;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong SplitMix64(ref ulong state)
    {
        var result = state += 0x9E3779B97f4A7C15;
        result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9;
        result = (result ^ (result >> 27)) * 0x94D049BB133111EB;
        return result ^ (result >> 31);
    }

    public unsafe Xoshiro256StarStar()
    {
        /*ulong* ptr = stackalloc ulong[4];
        do
        {
            Interop.GetRandomBytes((byte*)ptr, 4 * sizeof(ulong));
            this.ss0 = ptr[0];
            this.ss1 = ptr[1];
            this.ss2 = ptr[2];
            this.ss3 = ptr[3];
        }
        while ((this.ss0 | this.ss1 | this.ss2 | this.ss3) == 0); // at least one value must be non-zero*/

        this.ss0 = 1;
    }

    public Xoshiro256StarStar(ulong seed)
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint NextUInt() => (uint)(this.NextULong() >> 32);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ulong NextULong()
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

    public int NextInt() => (int)(this.NextUInt() >> 1);

    public int NextInt(int maxValue)
    {
        if (maxValue > 1)
        {
            // Narrow down to the smallest range [0, 2^bits] that contains maxValue.
            // Then repeatedly generate a value in that outer range until we get one within the inner range.
            int bits = Log2Ceiling((uint)maxValue);
            while (true)
            {
                ulong result = this.NextULong() >> ((sizeof(ulong) * 8) - bits);
                if (result < (uint)maxValue)
                {
                    return (int)result;
                }
            }
        }

        return 0;
    }

    public int NextInt(int minValue, int maxValue)
    {
        ulong exclusiveRange = (ulong)((long)maxValue - minValue);

        if (exclusiveRange > 1)
        {
            int bits = Log2Ceiling(exclusiveRange);
            while (true)
            {
                ulong result = this.NextULong() >> ((sizeof(ulong) * 8) - bits);
                if (result < exclusiveRange)
                {
                    return (int)result + minValue;
                }
            }
        }

        return minValue;
    }

    public long NextLong() => (long)(this.NextULong() >> 1);

    public long NextLong(long maxValue)
    {
        if (maxValue > 1)
        {
            // Narrow down to the smallest range [0, 2^bits] that contains maxValue.
            // Then repeatedly generate a value in that outer range until we get one within the inner range.
            int bits = Log2Ceiling((ulong)maxValue);
            while (true)
            {
                ulong result = this.NextULong() >> ((sizeof(ulong) * 8) - bits);
                if (result < (ulong)maxValue)
                {
                    return (long)result;
                }
            }
        }

        return 0;
    }

    public long NextLong(long minValue, long maxValue)
    {
        var exclusiveRange = (ulong)(maxValue - minValue);

        if (exclusiveRange > 1)
        {
            var bits = Log2Ceiling(exclusiveRange);
            while (true)
            {
                var result = this.NextULong() >> ((sizeof(ulong) * 8) - bits);
                if (result < exclusiveRange)
                {
                    return (long)result + minValue;
                }
            }
        }

        return minValue;
    }

    public unsafe void NextBytes(Span<byte> buffer)
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

    /// <summary>
    /// [0,1)<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A double-precision floating point number that is greater than or equal to 0.0, and less than 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble() => (this.NextULong() >> 11) * (1.0 / 9007199254740992.0);

    /// <summary>
    /// [0,1]<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than or equal to 1.0.
    /// </summary>
    /// <returns>A double-precision floating-point number that is greater than or equal to 0.0, and less than or equal to 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble2() => (this.NextULong() >> 11) * (1.0 / 9007199254740991.0);

    /// <summary>
    /// (0,1)<br/>
    /// Returns a random floating-point number that is greater than 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A double-precision floating-point number that is greater than 0.0, and less than 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble3() => ((this.NextULong() >> 12) + 0.5) * (1.0 / 4503599627370496.0);

    /// <summary>
    /// [0,1)<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A single-precision floating point number that is greater than or equal to 0.0, and less than 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public float NextSingle() => (this.NextULong() >> 40) * (1.0f / 16777216.0f);
}
