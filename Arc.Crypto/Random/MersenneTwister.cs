// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

#pragma warning disable SA1310 // Field names should not contain underscore

using System;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

/// <summary>
/// Represents a pseudo-random number generator based on Mersenne Twister.<br/>
/// This class is NOT thread-safe.<br/>
/// Consider using lock statement or ObjectPool in multi-threaded application.
/// </summary>
public class MersenneTwister
{
    public const int BufferSize = NN * sizeof(ulong);
    private const int NN = 312;
    private const int MM = 156;
    private const ulong MATRIX_A = 0xB5026F5AA96619E9UL;
    private const ulong UM = 0xFFFFFFFF80000000UL;
    private const ulong LM = 0x7FFFFFFFUL;
    private static ulong[] mag01 = new ulong[] { 0UL, MATRIX_A };

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class.<br/>
    /// The default seed is 5489UL.
    /// </summary>
    public MersenneTwister()
    {
        this.Reset(5489UL);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class.<br/>
    /// </summary>
    /// <param name="seed">seed.</param>
    public MersenneTwister(uint seed)
    {
        this.Reset(seed);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class.<br/>
    /// </summary>
    /// <param name="seed">seed.</param>
    public MersenneTwister(ulong seed)
    {
        this.Reset(seed);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class.<br/>
    /// </summary>
    /// <param name="seedArray">The array of seeds.</param>
    public MersenneTwister(ulong[] seedArray)
    {
        this.Reset(seedArray);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class.<br/>
    /// </summary>
    /// <param name="seedArray">The array of seeds.</param>
    public MersenneTwister(byte[] seedArray)
    {
        this.Reset(seedArray);
    }

    /// <summary>
    /// Reset a state vector with the specified seed.
    /// </summary>
    /// <param name="seed">seed.</param>
    public void Reset(ulong seed)
    {
        this.nextUIntIsAvailable = false;
        this.nextUInt = 0;
        this.mt[0] = seed;
        for (this.mti = 1; this.mti < NN; this.mti++)
        {
            this.mt[this.mti] = (6364136223846793005UL * (this.mt[this.mti - 1] ^ (this.mt[this.mti - 1] >> 62))) + this.mti;
        }
    }

    /// <summary>
    /// Reset state vectors with the specified seeds.
    /// </summary>
    /// <param name="seedArray">The array of seeds.</param>
    public unsafe void Reset(byte[] seedArray)
    {
        var seedLength = seedArray.Length / sizeof(ulong);
        fixed (byte* seed = seedArray)
        {
            this.Reset((ulong*)seed, seedLength);
        }
    }

    /// <summary>
    /// Reset state vectors with the specified seeds.
    /// </summary>
    /// <param name="seedArray">The array of seeds.</param>
    public unsafe void Reset(ulong[] seedArray)
    {
        fixed (ulong* seed = seedArray)
        {
            this.Reset(seed, seedArray.Length);
        }
    }

    /// <summary>
    /// [0, 2^64-1]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 64-bit unsigned integer [0, 2^64-1].</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ulong NextULong()
    {
        if (this.mti >= NN)
        {
            this.Generate();
        }

        var x = this.mt[this.mti++];
        x ^= (x >> 29) & 0x5555555555555555UL;
        x ^= (x << 17) & 0x71D67FFFEDA60000UL;
        x ^= (x << 37) & 0xFFF7EEE000000000UL;
        x ^= x >> 43;
        return x;
    }

    /// <summary>
    /// [0, long.MaxValue]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 64-bit signed integer [0, long.MaxValue].</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public long NextLong() => (long)(this.NextULong() >> 1);

    /// <summary>
    /// [0, 2^32-1]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 32-bit unsigned integer [0, 2^32-1].</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint NextUInt()
    {
        if (this.nextUIntIsAvailable)
        {
            this.nextUIntIsAvailable = false;
            return this.nextUInt;
        }
        else
        {
            var u = this.NextULong();
            this.nextUInt = (uint)(u >> 32);
            this.nextUIntIsAvailable = true;
            return (uint)u;
        }
    }

    /// <summary>
    /// [0, int.MaxValue]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 32-bit signed integer [0, int.MaxValue].</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int NextInt() => (int)(this.NextUInt() >> 1);

    /// <summary>
    /// [0, maxValue)<br/>
    /// Returns a random integer.
    /// </summary>
    /// <param name="maxValue">The exclusive upper bound of the random number to be generated.<br/>
    /// maxValue must be greater than or equal to 0.</param>
    /// <returns>A 32-bit unsigned integer [0, maxValue).</returns>
    public int NextInt(int maxValue)
    {// return (int)(this.NextDouble() * maxValue);
        if (maxValue > 1)
        {
            int bits = Xoshiro256StarStar.Log2Ceiling((uint)maxValue);
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

    /// <summary>
    /// [minValue, maxValue)<br/>
    /// Returns a random integer.
    /// </summary>
    /// <param name="minValue">The inclusive lower bound of the random number returned.</param>
    /// <param name="maxValue">The exclusive upper bound of the random number returned.<br/>
    /// maxValue must be greater than or equal to minValue.</param>
    /// <returns>A 32-bit signed integer [minValue, maxValue).</returns>
    public int NextInt(int minValue, int maxValue)
    {
        if (minValue > maxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(minValue), $"'{nameof(minValue)}' cannot be greater than '{nameof(maxValue)}'");
        }

        return (int)((long)(this.NextDouble() * ((long)maxValue - minValue)) + minValue);
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
    public double NextDouble2() => (this.NextULong() >> 11) * (1.0 / 9007199254740991);

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

    /// <summary>
    /// Fills the elements of a specified span of bytes with random numbers.
    /// </summary>
    /// <param name="buffer">The array to be filled with random numbers.</param>
    public unsafe void NextBytes(Span<byte> buffer)
    {
        var remaining = buffer.Length;
        fixed (byte* pb = buffer)
        {
            byte* dest = pb;
            while (remaining >= sizeof(ulong))
            {
                *(ulong*)dest = this.NextULong();
                dest += sizeof(ulong);
                remaining -= sizeof(ulong);
            }

            while (remaining >= sizeof(uint))
            {
                *(uint*)dest = this.NextUInt();
                dest += sizeof(uint);
                remaining -= sizeof(uint);
            }

            if (remaining == 0)
            {
                return;
            }
            else
            {
                var u = this.NextUInt();
                byte* pu = (byte*)&u;
                while (remaining-- > 0)
                {
                    *dest++ = *pu++;
                }
            }
        }
    }

    private unsafe void Reset(ulong* seedArray, int seedLength)
    {
        this.Reset(19650218UL);

        var i = 1UL;
        var j = 0UL;
        var k = (ulong)((seedLength < NN) ? NN : seedLength);
        var seedLength2 = (ulong)seedLength;
        for (; k > 0; k--)
        {
            this.mt[i] = (this.mt[i] ^ ((this.mt[i - 1] ^ (this.mt[i - 1] >> 62)) * 3935559000370003845UL)) + seedArray[j] + j;
            i++;
            j++;

            if (i >= NN)
            {
                this.mt[0] = this.mt[NN - 1];
                i = 1;
            }

            if (j >= seedLength2)
            {
                j = 0;
            }
        }

        for (k = NN - 1; k > 0; k--)
        {
            this.mt[i] = (this.mt[i] ^ ((this.mt[i - 1] ^ (this.mt[i - 1] >> 62)) * 2862933555777941757UL)) - i;

            i++;
            if (i >= NN)
            {
                this.mt[0] = this.mt[NN - 1];
                i = 1;
            }
        }

        this.mt[0] = 1UL << 63;
    }

    private void Generate()
    {
        int i;
        ulong x;
        for (i = 0; i < NN - MM; i++)
        {
            x = (this.mt[i] & UM) | (this.mt[i + 1] & LM);
            this.mt[i] = this.mt[i + MM] ^ (x >> 1) ^ mag01[(int)x & 1];
        }

        for (; i < NN - 1; i++)
        {
            x = (this.mt[i] & UM) | (this.mt[i + 1] & LM);
            this.mt[i] = this.mt[i + (MM - NN)] ^ (x >> 1) ^ mag01[(int)x & 1];
        }

        x = (this.mt[NN - 1] & UM) | (this.mt[0] & LM);
        this.mt[NN - 1] = this.mt[MM - 1] ^ (x >> 1) ^ mag01[(int)x & 1];

        this.mti = 0;
    }

    private ulong[] mt = new ulong[NN]; // The array for the state vector
    private ulong mti = NN + 1; // mti==NN+1 means mt[NN] is not initialized
    private uint nextUInt;
    private bool nextUIntIsAvailable;
}
