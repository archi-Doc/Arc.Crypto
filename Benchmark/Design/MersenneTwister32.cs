// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Numerics;

#pragma warning disable SA1310 // Field names should not contain underscore

namespace Benchmark;

public class MersenneTwister32
{
    // Period parameters
    private const int N = 624;
    private const int M = 397;
    private const uint MATRIX_A = 0x9908b0dfu; // constant vector a
    private const uint UPPER_MASK = 0x80000000u; // most significant w-r bits
    private const uint LOWER_MASK = 0x7fffffffu; // least significant r bits
    private uint[] mt = new uint[N]; // the array for the state vector
    private int mti = N + 1; // mti==N+1 means mt[N] is not initialized

    public MersenneTwister32()
    {
        this.Initialize(new uint[] { 0x123, 0x234, 0x345, 0x456 }); // set default seeds
    }

    public MersenneTwister32(uint s)
    {
        this.Initialize(s);
    }

    public MersenneTwister32(uint[] init_key)
    {
        this.Initialize(init_key);
    }

    /// <summary>
    /// Initialize MersenneTwister with seed.
    /// </summary>
    /// <param name="seed">seed</param>
    public void Initialize(uint seed)
    {
        mt[0] = seed & 0xffffffff;
        for (mti = 1; mti < N; mti++)
        {
            mt[mti] = (1812433253 * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + (uint)mti);
            /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier.
             * In the previous versions, MSBs of the seed affect
             * only MSBs of the array mt[].
             * 2002/01/09 modified by Makoto Matsumoto             */
            mt[mti] &= 0xffffffff;
            /* for >32 bit machines */
        }
    }

    // initialize by an array with array-length
    // init_key is the array for initializing keys
    // init_key.Length is its length
    public void Initialize(uint[] init_key)
    {
        this.Initialize(19650218);
        var i = 1;
        var j = 0;
        var k = (N > init_key.Length ? N : init_key.Length);
        for (; k != 0; k--)
        {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1664525)) + init_key[j] + (uint)j; /* non linear */
            mt[i] &= 0xffffffff; /* for WORDSIZE > 32 machines */
            i++; j++;
            if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
            if (j >= init_key.Length) { j = 0; }
        }
        for (k = N - 1; k != 0; k--)
        {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1566083941)) - (uint)i; // non linear
            mt[i] &= 0xffffffff; // for WORDSIZE > 32 machines
            i++;
            if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
        }
        mt[0] = 0x80000000; // MSB is 1; assuring non-zero initial array 
    }

    // generates a random number on [0,0xffffffff]-interval
    public uint genrand_uint32()
    {
        uint[] mag01 = new uint[] { 0x0, MATRIX_A };
        uint y = 0;
        // mag01[x] = x * MATRIX_A  for x=0,1
        if (mti >= N)
        {   // generate N words at one time
            int kk;
            if (mti == N + 1)
            {           // if init_genrand() has not been called,
                this.Initialize(5489);   // a default initial seed is used
            }
            for (kk = 0; kk < N - M; kk++)
            {
                y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1UL];
            }
            for (; kk < N - 1; kk++)
            {
                y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                mt[kk] = mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
            }
            y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
            mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ mag01[y & 0x1UL];
            mti = 0;
        }
        y = mt[mti++];
        // Tempering
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= (y >> 18);
        return y;
    }

    // generates a random floating point number on [0,1]
    public double NextDouble2()
    {
        return genrand_uint32() * (1.0 / 4294967295.0); // divided by 2^32-1
    }

    /// <summary>
    /// [0,1)<br/>
    /// Returns a random floating-point number that is greater than or equal to 0.0, and less than 1.0.
    /// </summary>
    /// <returns>A double-precision floating point number that is greater than or equal to 0.0, and less than 1.0.</returns>
    public double NextDouble()
    {
        return genrand_uint32() * (1.0 / 4294967296.0); // divided by 2^32
    }

    // generates a random integer number from 0 to N-1
    public int genrand_N(int iN)
    {
        return (int)(genrand_uint32() * (iN / 4294967296.0));
    }
}
