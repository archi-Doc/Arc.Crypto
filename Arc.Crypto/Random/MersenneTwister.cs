// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

#pragma warning disable SA1310 // Field names should not contain underscore

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// Represents a pseudo-random number generator based on the 64-bit Mersenne Twister (MT19937-64).<br/>
/// This class is NOT thread-safe.<br/>
/// Consider using a <see langword="lock"/> statement or <see cref="RandomVault"/> in multi-threaded applications.
/// </summary>
public class MersenneTwister : RandomUInt64Base
{
    /// <summary>
    /// The size in bytes of the internal state buffer.
    /// </summary>
    public const int StateSize = NN * sizeof(ulong);
    private const int NN = 312;
    private const int MM = 156;
    private const ulong MATRIX_A = 0xB5026F5AA96619E9UL;
    private const ulong UM = 0xFFFFFFFF80000000UL;
    private const ulong LM = 0x7FFFFFFFUL;

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class.<br/>
    /// The generator is initialized by random seeds (<see cref="RandomNumberGenerator"/>).
    /// </summary>
    public unsafe MersenneTwister()
    {
        const int seedLength = 16;
        Span<byte> span = stackalloc byte[seedLength * sizeof(ulong)];
        fixed (byte* b = span)
        {
            ulong* d = (ulong*)b;
            RandomNumberGenerator.Fill(span);
            this.Reset(d, seedLength);
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class with the specified seed.<br/>
    /// Equivalent to <see cref="MersenneTwister(ulong)"/>.
    /// </summary>
    /// <param name="seed">The seed value.</param>
    public MersenneTwister(uint seed)
    {
        this.Reset(seed);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class with the specified seed.
    /// </summary>
    /// <param name="seed">The seed value.</param>
    public MersenneTwister(ulong seed)
    {
        this.Reset(seed);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class with the specified seed words.
    /// </summary>
    /// <param name="seedArray">A non-empty array of 64-bit seed words.</param>
    /// <exception cref="ArgumentNullException"><paramref name="seedArray"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="seedArray"/> is empty.</exception>
    public MersenneTwister(ulong[] seedArray)
    {
        this.Reset(seedArray);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MersenneTwister"/> class with the specified seed bytes.
    /// </summary>
    /// <param name="seedArray">A non-empty byte array whose length is a multiple of 8, read as 64-bit seed words in native byte order.</param>
    /// <exception cref="ArgumentNullException"><paramref name="seedArray"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="seedArray"/> is zero or not a multiple of 8.</exception>
    public MersenneTwister(byte[] seedArray)
    {
        this.Reset(seedArray);
    }

    /// <summary>
    /// Resets the state with the specified seed.
    /// </summary>
    /// <param name="seed">The seed value.</param>
    public void Reset(ulong seed)
    {
        var mt = this.mt;
        mt[0] = seed;
        for (var i = 1; i < NN; i++)
        {
            mt[i] = (6364136223846793005UL * (mt[i - 1] ^ (mt[i - 1] >> 62))) + (ulong)i;
        }

        this.mti = NN;
    }

    /// <summary>
    /// Resets the state with the specified seed bytes.
    /// </summary>
    /// <param name="seedArray">A non-empty byte array whose length is a multiple of 8, read as 64-bit seed words in native byte order.</param>
    /// <exception cref="ArgumentNullException"><paramref name="seedArray"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="seedArray"/> is zero or not a multiple of 8.</exception>
    public unsafe void Reset(byte[] seedArray)
    {
        ArgumentNullException.ThrowIfNull(seedArray);
        if (seedArray.Length == 0 || (seedArray.Length % sizeof(ulong)) != 0)
        {
            throw new ArgumentException("The seed must contain a non-empty sequence of 64-bit words.", nameof(seedArray));
        }

        var seedLength = seedArray.Length / sizeof(ulong);
        fixed (byte* seed = seedArray)
        {
            this.Reset((ulong*)seed, seedLength);
        }
    }

    /// <summary>
    /// Resets the state with the specified seed words.
    /// </summary>
    /// <param name="seedArray">A non-empty array of 64-bit seed words.</param>
    /// <exception cref="ArgumentNullException"><paramref name="seedArray"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="seedArray"/> is empty.</exception>
    public unsafe void Reset(ulong[] seedArray)
    {
        ArgumentNullException.ThrowIfNull(seedArray);
        if (seedArray.Length == 0)
        {
            throw new ArgumentException("At least one seed is required.", nameof(seedArray));
        }

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
    public override ulong NextUInt64() => this.NextCore();

    /// <inheritdoc/>
    /// <remarks>Draws words directly from the generator state; an override of <see cref="NextUInt64"/> in a derived class is not used.</remarks>
    public override void NextBytes(Span<byte> destination)
    {
        while (destination.Length >= sizeof(ulong))
        {
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), this.NextCore());
            destination = destination.Slice(sizeof(ulong));
        }

        if (!destination.IsEmpty)
        {
            var u = this.NextCore();
            MemoryMarshal.AsBytes(new Span<ulong>(ref u)).Slice(0, destination.Length).CopyTo(destination);
        }
    }

    /*public uint NextUInt()
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
    }*/

    private unsafe void Reset(ulong* seedArray, int seedLength)
    {
        this.Reset(19650218UL);

        var mt = this.mt;
        var i = 1;
        var j = 0;
        var k = (seedLength < NN) ? NN : seedLength;
        for (; k > 0; k--)
        {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 62)) * 3935559000370003845UL)) + seedArray[j] + (ulong)j;
            i++;
            j++;

            if (i >= NN)
            {
                mt[0] = mt[NN - 1];
                i = 1;
            }

            if (j >= seedLength)
            {
                j = 0;
            }
        }

        for (k = NN - 1; k > 0; k--)
        {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 62)) * 2862933555777941757UL)) - (ulong)i;

            i++;
            if (i >= NN)
            {
                mt[0] = mt[NN - 1];
                i = 1;
            }
        }

        mt[0] = 1UL << 63;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ulong NextCore()
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

    private void Generate()
    {
        var mt = this.mt.AsSpan(0, NN);
        int i;
        ulong x;
        for (i = 0; i < NN - MM; i++)
        {
            x = (mt[i] & UM) | (mt[i + 1] & LM);
            mt[i] = mt[i + MM] ^ (x >> 1) ^ ((0UL - (x & 1)) & MATRIX_A);
        }

        for (; i < NN - 1; i++)
        {
            x = (mt[i] & UM) | (mt[i + 1] & LM);
            mt[i] = mt[i + (MM - NN)] ^ (x >> 1) ^ ((0UL - (x & 1)) & MATRIX_A);
        }

        x = (mt[NN - 1] & UM) | (mt[0] & LM);
        mt[NN - 1] = mt[MM - 1] ^ (x >> 1) ^ ((0UL - (x & 1)) & MATRIX_A);

        this.mti = 0;
    }

    private readonly ulong[] mt = new ulong[NN]; // The array for the state vector
    private int mti; // Index of the next state word; NN means the state must be regenerated
}
