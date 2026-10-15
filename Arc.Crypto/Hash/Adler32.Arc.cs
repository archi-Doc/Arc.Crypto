// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Arc.Crypto;

/// <summary>
/// Adler-32 checksum (RFC 1950). Not cryptographic.
/// </summary>
/// <remarks>
/// <see cref="GetHash(ReadOnlySpan{byte})"/>, <see cref="GetHash(byte[], int, int)"/> and <see cref="HashFinal"/> return the value in native byte order (<see cref="BitConverter.GetBytes(uint)"/>), which is little-endian on common platforms, not the big-endian order of the zlib trailer.<br/>
/// <see cref="HashFinal"/> does not reset the state; call <see cref="HashInitialize"/> before starting a new hash.
/// </remarks>
public class Adler32 : IHash
{
    /// <summary>
    /// Length of the hash in bytes.
    /// </summary>
    public const int HashLength = 4;

    private const uint Modulus = 65521; // Largest prime below 2^16.

    // Largest n with 255 * n * (n + 1) / 2 + (n + 1) * (Modulus - 1) < 2^32 (zlib NMAX): the sums stay below 2^32 between reductions.
    private const int NMax = 5552;

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
    /// Calculates the Adler-32 checksum of the input.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A 32bit hash.</returns>
    public static uint Hash32(ReadOnlySpan<byte> input)
    {
        var checksum = Update(1, input);

        // convert little endian to big endian.
        // return (checksum & 0xFF) << 24 | ((checksum >> 8) & 0xFF) << 16 | ((checksum >> 16) & 0xFF) << 8 | ((checksum >> 24) & 0xFF);
        return checksum;
    }

    /// <summary>
    /// Calculates the Adler-32 checksum of the string's UTF-16 code units in native byte order, not of its UTF-8 bytes.
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
        this.checksum = 1;
    }

    /// <inheritdoc/>
    public void HashUpdate(ReadOnlySpan<byte> input)
    {
        this.checksum = Update(this.checksum, input);
    }

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount) => this.HashUpdate(input.AsSpan(inputOffset, inputCount));

    /// <inheritdoc/>
    public byte[] HashFinal()
    {
        return BitConverter.GetBytes(this.checksum);
    }

    /// <summary>
    /// Scalar implementation. Takes and returns the running checksum (s2 &lt;&lt; 16 | s1, each below 65521).
    /// </summary>
    /// <param name="adler">The running checksum.</param>
    /// <param name="input">The input data.</param>
    /// <returns>The updated checksum.</returns>
    internal static uint UpdateScalar(uint adler, ReadOnlySpan<byte> input)
    {
        var s1 = adler & 0xFFFF;
        var s2 = adler >> 16;
        ref byte source = ref MemoryMarshal.GetReference(input);
        var length = (nuint)input.Length;

        while (length > 0)
        {
            var n = length < NMax ? length : NMax;
            length -= n;

            for (; n >= 8; n -= 8)
            {
                s1 += source;
                s2 += s1;
                s1 += Unsafe.Add(ref source, 1);
                s2 += s1;
                s1 += Unsafe.Add(ref source, 2);
                s2 += s1;
                s1 += Unsafe.Add(ref source, 3);
                s2 += s1;
                s1 += Unsafe.Add(ref source, 4);
                s2 += s1;
                s1 += Unsafe.Add(ref source, 5);
                s2 += s1;
                s1 += Unsafe.Add(ref source, 6);
                s2 += s1;
                s1 += Unsafe.Add(ref source, 7);
                s2 += s1;
                source = ref Unsafe.Add(ref source, 8);
            }

            for (; n > 0; n--)
            {
                s1 += source;
                s2 += s1;
                source = ref Unsafe.Add(ref source, 1);
            }

            s1 %= Modulus;
            s2 %= Modulus;
        }

        return (s2 << 16) | s1;
    }

    /// <summary>
    /// SSSE3 implementation processing 16-byte blocks; the remaining bytes go to <see cref="UpdateScalar(uint, ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="adler">The running checksum.</param>
    /// <param name="input">The input data.</param>
    /// <returns>The updated checksum.</returns>
    internal static uint UpdateVector128(uint adler, ReadOnlySpan<byte> input)
    {
        Debug.Assert(Ssse3.IsSupported, "SSSE3 is required.");

        const int BlockSize = 16;
        var s1 = adler & 0xFFFF;
        var s2 = adler >> 16;
        ref byte source = ref MemoryMarshal.GetReference(input);
        var length = (nuint)input.Length;

        // Byte j of a block is added to s2 (BlockSize - j) times within the block.
        var taps = Vector128.Create(16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, (sbyte)1);
        var ones = Vector128<short>.One;
        while (length >= BlockSize)
        {
            var blocks = (length < NMax ? length : NMax) / BlockSize;
            length -= blocks * BlockSize;
            s2 += s1 * (uint)(blocks * BlockSize);

            var vps = Vector128<uint>.Zero; // Sum of vs1 before each block.
            var vs1 = Vector128<uint>.Zero;
            var vs2 = Vector128<uint>.Zero;
            do
            {
                var bytes = Vector128.LoadUnsafe(ref source);
                vps += vs1;
                vs1 += Sse2.SumAbsoluteDifferences(bytes, Vector128<byte>.Zero).AsUInt32();
                vs2 += Sse2.MultiplyAddAdjacent(Ssse3.MultiplyAddAdjacent(bytes, taps), ones).AsUInt32();
                source = ref Unsafe.Add(ref source, BlockSize);
            }
            while (--blocks > 0);

            vs2 += vps << 4;
            s1 += Vector128.Sum(vs1);
            s2 += Vector128.Sum(vs2);
            s1 %= Modulus;
            s2 %= Modulus;
        }

        return UpdateScalar((s2 << 16) | s1, MemoryMarshal.CreateReadOnlySpan(ref source, (int)length));
    }

    /// <summary>
    /// AVX2 implementation processing 32-byte blocks; the remaining bytes go to <see cref="UpdateVector128(uint, ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="adler">The running checksum.</param>
    /// <param name="input">The input data.</param>
    /// <returns>The updated checksum.</returns>
    internal static uint UpdateVector256(uint adler, ReadOnlySpan<byte> input)
    {
        Debug.Assert(Avx2.IsSupported, "AVX2 is required.");

        const int BlockSize = 32;
        var s1 = adler & 0xFFFF;
        var s2 = adler >> 16;
        ref byte source = ref MemoryMarshal.GetReference(input);
        var length = (nuint)input.Length;

        // Byte j of a block is added to s2 (BlockSize - j) times within the block.
        var taps = Vector256.Create(32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, (sbyte)1);
        var ones = Vector256<short>.One;
        while (length >= BlockSize)
        {
            var blocks = (length < NMax ? length : NMax) / BlockSize;
            length -= blocks * BlockSize;
            s2 += s1 * (uint)(blocks * BlockSize);

            var vps = Vector256<uint>.Zero; // Sum of vs1 before each block.
            var vs1 = Vector256<uint>.Zero;
            var vs2 = Vector256<uint>.Zero;
            do
            {
                var bytes = Vector256.LoadUnsafe(ref source);
                vps += vs1;
                vs1 += Avx2.SumAbsoluteDifferences(bytes, Vector256<byte>.Zero).AsUInt32();
                vs2 += Avx2.MultiplyAddAdjacent(Avx2.MultiplyAddAdjacent(bytes, taps), ones).AsUInt32();
                source = ref Unsafe.Add(ref source, BlockSize);
            }
            while (--blocks > 0);

            vs2 += vps << 5;
            s1 += Vector256.Sum(vs1);
            s2 += Vector256.Sum(vs2);
            s1 %= Modulus;
            s2 %= Modulus;
        }

        return UpdateVector128((s2 << 16) | s1, MemoryMarshal.CreateReadOnlySpan(ref source, (int)length));
    }

    private static uint Update(uint adler, ReadOnlySpan<byte> input)
    {
        // The 128-bit path has a cheaper final reduction and is faster below about 128 bytes.
        if (Avx2.IsSupported && input.Length >= 128)
        {
            return UpdateVector256(adler, input);
        }
        else if (Ssse3.IsSupported && input.Length >= 16)
        {
            return UpdateVector128(adler, input);
        }

        return UpdateScalar(adler, input);
    }
}
