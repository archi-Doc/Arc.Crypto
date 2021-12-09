// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arc.Crypto;

/// <summary>
/// Represents a pseudo-random number generator based on Xorshift.<br/>
/// </summary>
public class Xorshift : RandomUInt64
{
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

    public override ulong NextUInt64()
    {
        this.seed ^= this.seed << 13;
        this.seed ^= this.seed >> 7;
        this.seed ^= this.seed << 17;

        return this.seed;
    }

    private ulong seed;
}
