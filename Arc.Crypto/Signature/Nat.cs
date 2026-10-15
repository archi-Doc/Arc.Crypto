// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;

namespace Arc.Crypto.EC;

#pragma warning disable SA1405 // Debug.Assert should provide message text

internal abstract class Nat
{
    /// <summary>
    /// Adds <c>2^32 + x</c> to the <paramref name="len"/>-word value <paramref name="z"/> in place.
    /// </summary>
    /// <param name="len">The number of words in <paramref name="z"/>; at least 2.</param>
    /// <param name="x">The low word of the addend.</param>
    /// <param name="z">The value, least significant word first.</param>
    /// <returns>The carry out of the top word (0 or 1).</returns>
    public static uint Add33To(int len, uint x, Span<uint> z)
    {
        ulong c = (ulong)z[0] + x;
        z[0] = (uint)c;
        c >>= 32;
        c += (ulong)z[1] + 1;
        z[1] = (uint)c;
        c >>= 32;
        return c == 0 ? 0 : IncAt(len, z, 2);
    }

    /// <summary>
    /// Increments the <paramref name="len"/>-word value <paramref name="z"/> at word <paramref name="zPos"/>, propagating the carry upward.
    /// </summary>
    /// <param name="len">The number of words in the value.</param>
    /// <param name="z">The value, least significant word first.</param>
    /// <param name="zPos">The index of the word to increment.</param>
    /// <returns>The carry out of the top word (0 or 1).</returns>
    public static uint IncAt(int len, Span<uint> z, int zPos)
    {
        Debug.Assert(zPos <= len);
        for (int i = zPos; i < len; ++i)
        {
            if (++z[i] != uint.MinValue)
            {
                return 0;
            }
        }

        return 1;
    }

    /// <summary>
    /// Increments the <paramref name="len"/>-word value starting at <c>z[zOff]</c> at its word <paramref name="zPos"/>, propagating the carry upward.
    /// </summary>
    /// <param name="len">The number of words in the value.</param>
    /// <param name="z">The span holding the value, least significant word first.</param>
    /// <param name="zOff">The word offset of the value in <paramref name="z"/>.</param>
    /// <param name="zPos">The index, relative to <paramref name="zOff"/>, of the word to increment.</param>
    /// <returns>The carry out of the top word (0 or 1).</returns>
    public static uint IncAt(int len, Span<uint> z, int zOff, int zPos)
    {
        Debug.Assert(zPos <= len);
        for (int i = zPos; i < len; ++i)
        {
            if (++z[zOff + i] != uint.MinValue)
            {
                return 0;
            }
        }

        return 1;
    }
}
