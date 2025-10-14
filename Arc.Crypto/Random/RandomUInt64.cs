// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

public abstract class RandomUInt64
{
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

    /// <summary>
    /// [0, 2^64-1]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 64-bit unsigned integer [0, 2^64-1].</returns>
    public abstract ulong NextUInt64();

    /// <summary>
    /// [0, <see cref="long.MaxValue"/>]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 64-bit signed integer [0, long.MaxValue].</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public long NextInt63() => (long)(this.NextUInt64() >> 1);

    /// <summary>
    /// [0, 2^32-1]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 32-bit unsigned integer [0, 2^32-1].</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint NextUInt32() => (uint)(this.NextUInt64() >> 32);

    /// <summary>
    /// [int.MinValue, int.MaxValue]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 32-bit signed integer [int.MinValue, int.MaxValue].</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int NextInt32() => unchecked((int)(this.NextUInt64() >> 32));

    /// <summary>
    /// [0, int.MaxValue]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 32-bit signed integer [0, int.MaxValue].</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int NextInt31() => (int)(this.NextUInt64() >> 33);

    /// <summary>
    /// [0, maxValue)<br/>
    /// Returns a random integer.
    /// </summary>
    /// <param name="maxValue">The exclusive upper bound of the random number to be generated.<br/>
    /// maxValue must be greater than or equal to 0.</param>
    /// <returns>A 32-bit unsigned integer [0, maxValue).</returns>
    public int NextInt32(int maxValue)
    {
        if (maxValue > 1)
        {
            int bits = Log2Ceiling((uint)maxValue);
            while (true)
            {
                ulong result = this.NextUInt64() >> ((sizeof(ulong) * 8) - bits);
                if (result < (uint)maxValue)
                {
                    return (int)result;
                }
            }
        }

        return 0;
    }

    /// <summary>
    /// [minValue, maxValue)<br/>
    /// Returns a random integer.
    /// </summary>
    /// <param name="minValue">The inclusive lower bound of the random number returned.</param>
    /// <param name="maxValue">The exclusive upper bound of the random number returned.<br/>
    /// maxValue must be greater than or equal to minValue.</param>
    /// <returns>A 32-bit signed integer [minValue, maxValue).</returns>
    public int NextInt32(int minValue, int maxValue)
    {
        ulong exclusiveRange = (ulong)((long)maxValue - minValue);

        if (exclusiveRange > 1)
        {
            int bits = Log2Ceiling(exclusiveRange);
            while (true)
            {
                ulong result = this.NextUInt64() >> ((sizeof(ulong) * 8) - bits);
                if (result < exclusiveRange)
                {
                    return (int)result + minValue;
                }
            }
        }

        return minValue;
    }

    /// <summary>
    /// [0, maxValue)<br/>
    /// Returns a random integer.
    /// </summary>
    /// <param name="maxValue">The exclusive upper bound of the random number to be generated.<br/>
    /// maxValue must be greater than or equal to 0.</param>
    /// <returns>A 64-bit unsigned integer [0, maxValue).</returns>
    public long NextInt64(long maxValue)
    {
        if (maxValue > 1)
        {
            int bits = Log2Ceiling((ulong)maxValue);
            while (true)
            {
                ulong result = this.NextUInt64() >> ((sizeof(ulong) * 8) - bits);
                if (result < (ulong)maxValue)
                {
                    return (long)result;
                }
            }
        }

        return 0;
    }

    /// <summary>
    /// [minValue, maxValue)<br/>
    /// Returns a random integer.
    /// </summary>
    /// <param name="minValue">The inclusive lower bound of the random number returned.</param>
    /// <param name="maxValue">The exclusive upper bound of the random number returned.<br/>
    /// maxValue must be greater than or equal to minValue.</param>
    /// <returns>A 64-bit signed integer [minValue, maxValue).</returns>
    public long NextInt64(long minValue, long maxValue)
    {
        var exclusiveRange = (ulong)(maxValue - minValue);

        if (exclusiveRange > 1)
        {
            var bits = Log2Ceiling(exclusiveRange);
            while (true)
            {
                var result = this.NextUInt64() >> ((sizeof(ulong) * 8) - bits);
                if (result < exclusiveRange)
                {
                    return (long)result + minValue;
                }
            }
        }

        return minValue;
    }

    /// <summary>
    /// [0,1)<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A double-precision floating point number that is greater than or equal to 0.0, and less than 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble() => (this.NextUInt64() >> 11) * (1.0 / 9007199254740992.0);

    /// <summary>
    /// [0,1]<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than or equal to 1.0.
    /// </summary>
    /// <returns>A double-precision floating-point number that is greater than or equal to 0.0, and less than or equal to 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble2() => (this.NextUInt64() >> 11) * (1.0 / 9007199254740991.0);

    /// <summary>
    /// (0,1)<br/>
    /// Returns a random floating-point number that is greater than 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A double-precision floating-point number that is greater than 0.0, and less than 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble3() => ((this.NextUInt64() >> 12) + 0.5) * (1.0 / 4503599627370496.0);

    /// <summary>
    /// [0,1)<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A single-precision floating point number that is greater than or equal to 0.0, and less than 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public float NextSingle() => (this.NextUInt64() >> 40) * (1.0f / 16777216.0f);

    /// <summary>
    /// Fills the elements of a specified span of bytes with random numbers.
    /// </summary>
    /// <param name="destination">The span to fill with random numbers.</param>
    public unsafe virtual void NextBytes(Span<byte> destination)
    {
        var remaining = destination.Length;
        fixed (byte* pb = destination)
        {
            byte* dest = pb;
            while (remaining >= sizeof(ulong))
            {
                *(ulong*)dest = this.NextUInt64();
                dest += sizeof(ulong);
                remaining -= sizeof(ulong);
            }

            if (remaining == 0)
            {
                return;
            }

            // 0 < remaining < 8
            var u = this.NextUInt64();
            if (remaining >= sizeof(uint))
            {
                *(uint*)dest = (uint)u;
                dest += sizeof(uint);
                remaining -= sizeof(uint);
                u >>= 32;
            }

            // 0 < remaining < 4
            byte* pu = (byte*)&u;
            while (remaining-- > 0)
            {
                *dest++ = *pu++;
            }
        }
    }
}
