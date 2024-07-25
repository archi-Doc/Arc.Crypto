// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// Adler32 Hash Class.
/// </summary>
public class Adler32 : IHash
{
    /// <summary>
    /// Length of the hash in bytes.
    /// </summary>
    public const int HashLength = 4;

    private uint checksum = 1;

    /// <summary>
    /// Initializes a new instance of the <see cref="Adler32"/> class.
    /// </summary>
    public Adler32()
    {
    }

    /// <inheritdoc/>
    public string HashName => "Adler-32";

    /// <inheritdoc/>
    public uint HashBits => 32;

    /// <inheritdoc/>
    public bool IsCryptographic => false;

    /// <summary>
    /// Calculates Adler-32 hash.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A 32bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe uint Hash32(ReadOnlySpan<byte> input)
    {
        uint checksum = 1;
        var length = input.Length;
        int position = 0;
        int n;
        uint s1 = checksum & 0xFFFF;
        uint s2 = checksum >> 16;

        while (length > 0)
        {
            n = (length < 3800) ? length : 3800;
            length -= n;

            while (--n >= 0)
            {
                s1 = s1 + (uint)(input[position++] & 0xFF);
                s2 = s2 + s1;
            }

            s1 %= 65521;
            s2 %= 65521;
        }

        checksum = (s2 << 16) | s1;

        // convert little endian to big endian.
        // return (checksum & 0xFF) << 24 | ((checksum >> 8) & 0xFF) << 16 | ((checksum >> 16) & 0xFF) << 8 | ((checksum >> 24) & 0xFF);
        return checksum;
    }

    /// <summary>
    /// Calculates a 32bit hash from the given string.
    /// </summary>
    /// <param name="str">The string containing the characters to calculate the hash from.</param>
    /// <returns>A 32bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe uint Hash32(string str) => Hash32(MemoryMarshal.Cast<char, byte>(str));

    /// <inheritdoc/>
    public byte[] GetHash(ReadOnlySpan<byte> input) => BitConverter.GetBytes(Hash32(input));

    /// <inheritdoc/>
    public byte[] GetHash(byte[] input, int inputOffset, int inputCount) => BitConverter.GetBytes(Hash32(input.AsSpan(inputOffset, inputCount)));

    /// <inheritdoc/>
    public void HashInitialize()
    {
        this.checksum = 1;
    }

    /// <inheritdoc/>
    public void HashUpdate(ReadOnlySpan<byte> input)
    {
        int n;
        uint s1 = this.checksum & 0xFFFF;
        uint s2 = this.checksum >> 16;

        int position = 0;
        var len = input.Length;
        while (len > 0)
        {
            n = (len < 3800) ? len : 3800;
            len -= n;

            while (--n >= 0)
            {
                s1 = s1 + (uint)(input[position++] & 0xFF);
                s2 = s2 + s1;
            }

            s1 %= 65521;
            s2 %= 65521;
        }

        this.checksum = (s2 << 16) | s1;
    }

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount) => this.HashUpdate(input.AsSpan(inputOffset, inputCount));

    /// <inheritdoc/>
    public byte[] HashFinal()
    {
        return BitConverter.GetBytes(this.checksum);
    }
}
