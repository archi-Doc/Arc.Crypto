// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// CRC32 Hash Class.
/// </summary>
public class Crc32 : IHash
{
    /// <summary>
    /// Length of the hash in bytes.
    /// </summary>
    public const int HashLength = 4;

    private const uint Crc32Mask = 0xffffffff;

    private const uint Polynomial = 0xEDB88320; // Reflected IEEE 802.3 polynomial.

    /// <summary>
    /// Eight consecutive 256-entry tables for slicing-by-8; the first one is the classic byte-wise table.
    /// </summary>
    private static readonly uint[] Crc32Table = CreateTable();

    private uint crcValue;

    /// <summary>
    /// Initializes a new instance of the <see cref="Crc32"/> class.
    /// </summary>
    public Crc32()
    {
        this.HashInitialize();
    }

    /// <inheritdoc/>
    public string HashName => "CRC-32";

    /// <inheritdoc/>
    public uint HashBits => 32;

    /// <inheritdoc/>
    public bool IsCryptographic => false;

    /// <summary>
    /// Calculates CRC32 hash.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A 32bit hash.</returns>
    public static uint Hash32(ReadOnlySpan<byte> input)
        => Update(Crc32Mask, input) ^ Crc32Mask;

    /// <summary>
    /// Calculates a 32bit hash from the given string.
    /// </summary>
    /// <param name="str">The string containing the characters to calculate.</param>
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
        this.crcValue = Crc32Mask;
    }

    /// <inheritdoc/>
    public void HashUpdate(ReadOnlySpan<byte> input)
    {
        this.crcValue = Update(this.crcValue, input);
    }

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount) => this.HashUpdate(input.AsSpan(inputOffset, inputCount));

    /// <inheritdoc/>
    public byte[] HashFinal()
    {
        this.crcValue ^= Crc32Mask;
        var result = BitConverter.GetBytes(this.crcValue);
        this.HashInitialize();
        return result;
    }

    private static uint[] CreateTable()
    {
        var table = new uint[8 * 256];
        for (uint i = 0; i < 256; i++)
        {
            var crc = i;
            for (var k = 0; k < 8; k++)
            {
                crc = (crc >> 1) ^ (Polynomial & (0u - (crc & 1)));
            }

            table[i] = crc;
        }

        // Table k advances a byte followed by k zero bytes.
        for (var i = 256; i < table.Length; i++)
        {
            var previous = table[i - 256];
            table[i] = (previous >> 8) ^ table[previous & 0xFF];
        }

        return table;
    }

    private static uint Update(uint crc, ReadOnlySpan<byte> input)
    {
        ref uint table = ref MemoryMarshal.GetArrayDataReference(Crc32Table);
        ref byte source = ref MemoryMarshal.GetReference(input);
        var length = (nuint)input.Length;
        nuint i = 0;

        for (; length - i >= 8; i += 8)
        {// Slicing-by-8: eight independent table lookups per eight bytes.
            var one = ReadLittleEndian(ref Unsafe.Add(ref source, i)) ^ crc;
            var two = ReadLittleEndian(ref Unsafe.Add(ref source, i + 4));
            crc = Unsafe.Add(ref table, 0x700 | (one & 0xFF)) ^
                Unsafe.Add(ref table, 0x600 | ((one >> 8) & 0xFF)) ^
                Unsafe.Add(ref table, 0x500 | ((one >> 16) & 0xFF)) ^
                Unsafe.Add(ref table, 0x400 | (one >> 24)) ^
                Unsafe.Add(ref table, 0x300 | (two & 0xFF)) ^
                Unsafe.Add(ref table, 0x200 | ((two >> 8) & 0xFF)) ^
                Unsafe.Add(ref table, 0x100 | ((two >> 16) & 0xFF)) ^
                Unsafe.Add(ref table, two >> 24);
        }

        for (; i < length; i++)
        {
            crc = Unsafe.Add(ref table, (crc ^ Unsafe.Add(ref source, i)) & 0xFF) ^ (crc >> 8);
        }

        return crc;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ReadLittleEndian(ref byte source)
    {
        var value = Unsafe.ReadUnaligned<uint>(ref source);
        return BitConverter.IsLittleEndian ? value : BinaryPrimitives.ReverseEndianness(value);
    }
}
