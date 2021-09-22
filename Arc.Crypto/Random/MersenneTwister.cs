// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

#pragma warning disable SA1310 // Field names should not contain underscore

using System.Runtime.CompilerServices;

namespace Arc.Crypto;

/// <summary>
/// Represents a pseudo-random number generator based on Mersenne Twister.
/// </summary>
public class MersenneTwister
{
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
    /// Reset a state vector with the specified seed.
    /// </summary>
    /// <param name="seed">seed.</param>
    public void Reset(ulong seed)
    {
        this.mt[0] = seed;
        for (this.mti = 1; this.mti < NN; this.mti++)
        {
            this.mt[this.mti] = (6364136223846793005UL * (this.mt[this.mti - 1] ^ (this.mt[this.mti - 1] >> 62))) + this.mti;
        }
    }

    /// <summary>
    /// Reset a state vector with the specified seeds.
    /// </summary>
    /// <param name="seedArray">The array of seeds.</param>
    public void Reset(ulong[] seedArray)
    {
        this.Reset(19650218UL);

        var seedLength = (ulong)seedArray.Length;
        var i = 1UL;
        var j = 0UL;
        var k = (ulong)((seedArray.Length < NN) ? NN : seedArray.Length);
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

            if (j >= seedLength)
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

    /// <summary>
    /// [0, 2^64-1]<br/>
    /// Returns a non-negative random integer.
    /// </summary>
    /// <returns>A 64-bit unsigned integer that is greater than or equal to 0 and less than 2^64.</returns>
    public ulong NextULong()
    {
        int i;
        ulong x;
        if (this.mti >= NN)
        {
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

        x = this.mt[this.mti++];

        x ^= (x >> 29) & 0x5555555555555555UL;
        x ^= (x << 17) & 0x71D67FFFEDA60000UL;
        x ^= (x << 37) & 0xFFF7EEE000000000UL;
        x ^= x >> 43;

        return x;
    }

    /// <summary>
    /// [0, 2^32-1]<br/>
    /// Returns a non-negative random integer.
    /// </summary>
    /// <returns>A 32-bit unsigned integer that is greater than or equal to 0 and less than 2^32.</returns>
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
    /// [0,1)<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A double-precision floating point number that is greater than or equal to 0.0, and less than 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble()
    {
        return (this.NextULong() >> 11) * (1.0 / 9007199254740992.0);
    }

    /// <summary>
    /// [0,1]<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than or equal to 1.0.
    /// </summary>
    /// <returns>A double-precision floating-point number that is greater than or equal to 0.0, and less than or equal to 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble2()
    {
        return (this.NextULong() >> 11) * (1.0 / 9007199254740991);
    }

    /// <summary>
    /// (0,1)<br/>
    /// Returns a random floating-point number that is greater than 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A double-precision floating-point number that is greater than 0.0, and less than 1.0.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double NextDouble3()
    {
        return ((this.NextULong() >> 12) + 0.5) * (1.0 / 4503599627370496.0);
    }

    private ulong[] mt = new ulong[NN]; // The array for the state vector
    private ulong mti = NN + 1; // mti==NN+1 means mt[NN] is not initialized
    private uint nextUInt;
    private bool nextUIntIsAvailable;
}
