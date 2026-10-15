// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using ArmAes = System.Runtime.Intrinsics.Arm.Aes;
using ArmCrc32 = System.Runtime.Intrinsics.Arm.Crc32;

namespace Arc.Crypto;

/// <summary>
/// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), compatible with zlib and System.IO.Hashing.Crc32. Not cryptographic.
/// </summary>
/// <remarks>
/// <see cref="GetHash(ReadOnlySpan{byte})"/>, <see cref="GetHash(byte[], int, int)"/> and <see cref="HashFinal"/> return the value in native byte order (<see cref="BitConverter.GetBytes(uint)"/>), which is little-endian on common platforms.<br/>
/// <see cref="HashFinal"/> resets the state, so the instance is ready for a new hash.
/// </remarks>
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
    /// Gets a value indicating whether the carry-less multiplication path (PCLMULQDQ on x86, PMULL on Arm) is available.
    /// </summary>
    internal static bool IsVectorizedSupported => BitConverter.IsLittleEndian &&
        ((Pclmulqdq.IsSupported && Sse2.IsSupported) || (ArmAes.IsSupported && AdvSimd.IsSupported));

    /// <summary>
    /// Calculates the CRC-32 of the input.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A 32bit hash.</returns>
    public static uint Hash32(ReadOnlySpan<byte> input)
        => Update(Crc32Mask, input) ^ Crc32Mask;

    /// <summary>
    /// Calculates the CRC-32 of the string's UTF-16 code units in native byte order, not of its UTF-8 bytes.
    /// </summary>
    /// <param name="str">The string to hash.</param>
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

    /// <summary>
    /// Slicing-by-8 table implementation. Takes and returns the running register (initially 0xFFFFFFFF; the CRC is its complement).
    /// </summary>
    /// <param name="crc">The running register.</param>
    /// <param name="input">The input data.</param>
    /// <returns>The updated register.</returns>
    internal static uint UpdateTable(uint crc, ReadOnlySpan<byte> input)
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

    /// <summary>
    /// Arm64 CRC32X/CRC32B implementation (these instructions use the IEEE polynomial). Requires <see cref="ArmCrc32.Arm64.IsSupported"/>.
    /// </summary>
    /// <param name="crc">The running register.</param>
    /// <param name="input">The input data.</param>
    /// <returns>The updated register.</returns>
    internal static uint UpdateArm64(uint crc, ReadOnlySpan<byte> input)
    {
        Debug.Assert(ArmCrc32.Arm64.IsSupported, "Arm64 CRC32 instructions are required.");

        ref byte source = ref MemoryMarshal.GetReference(input);
        var length = (nuint)input.Length;
        nuint i = 0;

        for (; length - i >= 8; i += 8)
        {
            crc = ArmCrc32.Arm64.ComputeCrc32(crc, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, i)));
        }

        for (; i < length; i++)
        {
            crc = ArmCrc32.ComputeCrc32(crc, Unsafe.Add(ref source, i));
        }

        return crc;
    }

    // Ported from System.IO.Hashing.Crc32 (dotnet/runtime, Crc32.Vectorized.cs and VectorHelper.cs; MIT license, .NET Foundation).
    // Folds 4x128 bits (then 128 bits) at a time with carry-less multiplication, followed by a Barrett reduction, as described in
    // Intel's "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ Instruction" (2009).

    /// <summary>
    /// Carry-less multiplication implementation. Requires <see cref="IsVectorizedSupported"/> and at least 16 bytes of input.
    /// </summary>
    /// <param name="crc">The running register.</param>
    /// <param name="source">The input data.</param>
    /// <returns>The updated register.</returns>
    internal static uint UpdateVectorized(uint crc, ReadOnlySpan<byte> source)
    {
        Debug.Assert(IsVectorizedSupported && source.Length >= Vector128<byte>.Count, "Source cannot be vectorized.");

        ref byte srcRef = ref MemoryMarshal.GetReference(source);
        var length = source.Length;

        Vector128<ulong> kConstants;
        Vector128<ulong> x1; // Accumulator for the new CRC
        Vector128<ulong> x2;

        if (length >= Vector128<byte>.Count * 8)
        {
            x1 = Vector128.LoadUnsafe(ref srcRef).AsUInt64();
            x2 = Vector128.LoadUnsafe(ref srcRef, 16).AsUInt64();
            var x3 = Vector128.LoadUnsafe(ref srcRef, 32).AsUInt64();
            var x4 = Vector128.LoadUnsafe(ref srcRef, 48).AsUInt64();

            srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count * 4);
            length -= Vector128<byte>.Count * 4;

            // Load and XOR the initial CRC value
            x1 ^= Vector128.CreateScalar(crc).AsUInt64();

            kConstants = Vector128.Create(0x0154442bd4UL, 0x01c6e41596UL); // k1, k2

            // Parallel fold blocks of 64, if any.
            do
            {
                var y5 = Vector128.LoadUnsafe(ref srcRef).AsUInt64();
                var y6 = Vector128.LoadUnsafe(ref srcRef, 16).AsUInt64();
                var y7 = Vector128.LoadUnsafe(ref srcRef, 32).AsUInt64();
                var y8 = Vector128.LoadUnsafe(ref srcRef, 48).AsUInt64();

                x1 = FoldPolynomialPair(y5, x1, kConstants);
                x2 = FoldPolynomialPair(y6, x2, kConstants);
                x3 = FoldPolynomialPair(y7, x3, kConstants);
                x4 = FoldPolynomialPair(y8, x4, kConstants);

                srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count * 4);
                length -= Vector128<byte>.Count * 4;
            }
            while (length >= Vector128<byte>.Count * 4);

            // Fold into 128-bits.
            kConstants = Vector128.Create(0x01751997d0UL, 0x00ccaa009eUL); // k3, k4

            x1 = FoldPolynomialPair(x2, x1, kConstants);
            x1 = FoldPolynomialPair(x3, x1, kConstants);
            x1 = FoldPolynomialPair(x4, x1, kConstants);
        }
        else
        {
            // For shorter sources just load the first vector and XOR with the CRC
            x1 = Vector128.LoadUnsafe(ref srcRef).AsUInt64();
            x1 ^= Vector128.CreateScalar(crc).AsUInt64();

            srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
            length -= Vector128<byte>.Count;
        }

        // Single fold blocks of 16, if any.
        while (length >= Vector128<byte>.Count)
        {
            x1 = FoldPolynomialPair(Vector128.LoadUnsafe(ref srcRef).AsUInt64(), x1, Vector128.Create(0x01751997d0UL, 0x00ccaa009eUL));

            srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
            length -= Vector128<byte>.Count;
        }

        // Fold 128 bits to 64 bits.
        var bitmask = Vector128.Create(~0, 0, ~0, 0).AsUInt64();
        x1 = ShiftRightBytesInVector(x1, 8) ^
             CarrylessMultiplyLower(x1, Vector128.CreateScalar(0x00ccaa009eUL));
        x1 = CarrylessMultiplyLower(x1 & bitmask, Vector128.CreateScalar(0x0163cd6124UL)) ^ // k5, k0
             ShiftRightBytesInVector(x1, 4);

        // Reduce to 32 bits.
        kConstants = Vector128.Create(0x01db710641UL, 0x01f7011641UL); // polynomial
        x2 = CarrylessMultiplyLeftLowerRightUpper(x1 & bitmask, kConstants) & bitmask;
        x2 = CarrylessMultiplyLower(x2, kConstants);
        x1 ^= x2;

        // Process the remaining bytes, if any
        var result = x1.AsUInt32().GetElement(1);
        return length > 0
            ? UpdateScalar(result, MemoryMarshal.CreateReadOnlySpan(ref srcRef, length))
            : result;
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

    // Takes and returns the running register (initially 0xFFFFFFFF; the CRC is its complement), so calls can be chained.
    private static uint Update(uint crc, ReadOnlySpan<byte> input)
    {
        // The Arm CRC32 instructions are faster than the folding path for short inputs (System.IO.Hashing uses the same threshold).
        if (IsVectorizedSupported && input.Length >= Vector128<byte>.Count * (ArmCrc32.IsSupported ? 8 : 1))
        {
            return UpdateVectorized(crc, input);
        }

        return UpdateScalar(crc, input);
    }

    private static uint UpdateScalar(uint crc, ReadOnlySpan<byte> input)
        => ArmCrc32.Arm64.IsSupported ? UpdateArm64(crc, input) : UpdateTable(crc, input);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ReadLittleEndian(ref byte source)
    {
        var value = Unsafe.ReadUnaligned<uint>(ref source);
        return BitConverter.IsLittleEndian ? value : BinaryPrimitives.ReverseEndianness(value);
    }

    // Carry-less multiplies the upper and the lower halves of source and constants, and XORs both products into target.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> FoldPolynomialPair(Vector128<ulong> target, Vector128<ulong> source, Vector128<ulong> constants)
    {
        target ^= CarrylessMultiplyUpper(source, constants);
        target ^= CarrylessMultiplyLower(source, constants);
        return target;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> CarrylessMultiplyLower(Vector128<ulong> left, Vector128<ulong> right)
    {
        if (Pclmulqdq.IsSupported)
        {
            return Pclmulqdq.CarrylessMultiply(left, right, 0x00);
        }
        else
        {
            return ArmAes.PolynomialMultiplyWideningLower(left.GetLower(), right.GetLower());
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> CarrylessMultiplyUpper(Vector128<ulong> left, Vector128<ulong> right)
    {
        if (Pclmulqdq.IsSupported)
        {
            return Pclmulqdq.CarrylessMultiply(left, right, 0x11);
        }
        else
        {
            return ArmAes.PolynomialMultiplyWideningUpper(left, right);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> CarrylessMultiplyLeftLowerRightUpper(Vector128<ulong> left, Vector128<ulong> right)
    {
        if (Pclmulqdq.IsSupported)
        {
            return Pclmulqdq.CarrylessMultiply(left, right, 0x10);
        }
        else
        {
            return ArmAes.PolynomialMultiplyWideningLower(left.GetLower(), right.GetUpper());
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> ShiftRightBytesInVector(Vector128<ulong> operand, [ConstantExpected(Max = (byte)15)] byte numBytesToShift)
    {
        if (Sse2.IsSupported)
        {
            return Sse2.ShiftRightLogical128BitLane(operand, numBytesToShift);
        }
        else
        {
            return AdvSimd.ExtractVector128(operand.AsByte(), Vector128<byte>.Zero, numBytesToShift).AsUInt64();
        }
    }
}
