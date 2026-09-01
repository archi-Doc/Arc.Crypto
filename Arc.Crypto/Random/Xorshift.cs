// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// Represents a pseudo-random number generator based on Xorshift.<br/>
/// </summary>
public class Xorshift : RandomUInt64
{
    /// <summary>
    /// Advances a 32-bit Xorshift state in place. A zero state is replaced with the default seed.
    /// </summary>
    /// <param name="x">The state to advance.</param>
    public static void Xor32(ref uint x)
    {
        if (x == 0)
        {
            x = 2463534242;
            return;
        }

        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
    }

    /// <summary>
    /// Advances a 32-bit Xorshift state. A zero state is replaced with the default seed.
    /// </summary>
    /// <param name="x">The current state.</param>
    /// <returns>The next state.</returns>
    public static uint Xor32(uint x)
    {
        if (x == 0)
        {
            return 2463534242;
        }

        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        return x;
    }

    /// <summary>
    /// Advances a 64-bit Xorshift state in place. A zero state is replaced with the default seed.
    /// </summary>
    /// <param name="x">The state to advance.</param>
    public static void Xor64(ref ulong x)
    {
        if (x == 0)
        {
            x = 88172645463325252UL;
            return;
        }

        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
    }

    /// <summary>
    /// Advances a 64-bit Xorshift state. A zero state is replaced with the default seed.
    /// </summary>
    /// <param name="x">The current state.</param>
    /// <returns>The next state.</returns>
    public static ulong Xor64(ulong x)
    {
        if (x == 0)
        {
            return 88172645463325252UL;
        }

        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        return x;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Xorshift"/> class.<br/>
    /// The generator is initialized with the seed 88172645463325252UL.
    /// </summary>
    public unsafe Xorshift()
        : this(0)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Xorshift"/> class with the specified seed.
    /// </summary>
    /// <param name="seed">The seed.</param>
    public unsafe Xorshift(ulong seed)
    {
        if (seed == 0)
        {
            this.seed = 88172645463325252UL;
        }
        else
        {
            this.seed = seed;
        }
    }

    /// <summary>
    /// Generates the next random 64-bit unsigned integer.
    /// </summary>
    /// <returns>A random 64-bit unsigned integer.</returns>
    public override ulong NextUInt64()
    {
        this.seed ^= this.seed << 13;
        this.seed ^= this.seed >> 7;
        this.seed ^= this.seed << 17;

        return this.seed;
    }

    private ulong seed;
}
