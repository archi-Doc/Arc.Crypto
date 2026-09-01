// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto.EC;

/// <summary>
/// Base class for short Weierstrass elliptic curves of the form <c>y² = x³ + ax + b</c> over a prime field.<br/>
/// It provides point compression and seed (private key) validation; the field arithmetic is supplied by derived classes.
/// </summary>
public abstract class ECCurveBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ECCurveBase"/> class.
    /// </summary>
    /// <param name="uintLength">The number of 32-bit words in a field element.</param>
    /// <param name="hexQ">The field prime, as a big-endian hexadecimal string.</param>
    /// <param name="hexA">The curve coefficient <c>a</c>, as a big-endian hexadecimal string.</param>
    /// <param name="hexB">The curve coefficient <c>b</c>, as a big-endian hexadecimal string.</param>
    /// <param name="hexOrder">The order of the base point, as a big-endian hexadecimal string.</param>
    public ECCurveBase(int uintLength, string hexQ, string hexA, string hexB, string hexOrder)
    {
        this.UIntLength = uintLength;

        this.ByteQ = Hex.FromStringToByteArray(hexQ);
        // this.Q = new BigInteger(this.ByteQ, true, true);
        this.UIntQ = BytesToUInt(this.ByteQ);

        this.ByteA = Hex.FromStringToByteArray(hexA);
        // this.A = new BigInteger(this.ByteA, true, true);
        this.UIntA = BytesToUInt(this.ByteA);

        this.ByteB = Hex.FromStringToByteArray(hexB);
        // this.B = new BigInteger(this.ByteB, true, true);
        this.UIntB = BytesToUInt(this.ByteB);

        this.ByteOrder = Hex.FromStringToByteArray(hexOrder);
        // this.Order = new BigInteger(this.ByteOrder, true, true);
        this.UIntOrder = BytesToUInt(this.ByteOrder);

        uint[] BytesToUInt(ReadOnlySpan<byte> b)
        {
            var length = b.Length / 4;
            var x = new uint[length];
            for (var i = length - 1; i >= 0; i--)
            {
                var val = BitConverter.ToUInt32(b);
                val = (val >> 16) | (val << 16);
                val = ((val & 0xFF00FF00U) >> 8) | ((val & 0x00FF00FFU) << 8);
                x[i] = val;

                b = b.Slice(sizeof(uint));
            }

            return x;
        }
    }

    /// <summary>
    /// Gets the standard name of the curve, e.g. "secp256k1".
    /// </summary>
    public abstract string CurveName { get; }

    /// <summary>
    /// Gets the number of 32-bit words in a field element.
    /// </summary>
    public int UIntLength { get; }

    /// <summary>
    /// Gets the number of bytes in a field element.
    /// </summary>
    public int ByteLength => this.UIntLength * sizeof(uint);

    /// <summary>
    /// Gets the number of bits in a field element.
    /// </summary>
    public int BitLength => this.UIntLength * sizeof(uint) * 8;

    /*public BigInteger Q { get; }

    public BigInteger A { get; }

    public BigInteger B { get; }

    public BigInteger Order { get; }*/

    /// <summary>
    /// Gets the field prime as big-endian bytes.
    /// </summary>
    public byte[] ByteQ { get; }

    /// <summary>
    /// Gets the curve coefficient <c>a</c> as big-endian bytes.
    /// </summary>
    public byte[] ByteA { get; }

    /// <summary>
    /// Gets the curve coefficient <c>b</c> as big-endian bytes.
    /// </summary>
    public byte[] ByteB { get; }

    /// <summary>
    /// Gets the order of the base point as big-endian bytes.
    /// </summary>
    public byte[] ByteOrder { get; }

    /// <summary>
    /// Gets the field prime as 32-bit words, ordered from least to most significant.
    /// </summary>
    public uint[] UIntQ { get; }

    /// <summary>
    /// Gets the curve coefficient <c>a</c> as 32-bit words, ordered from least to most significant.
    /// </summary>
    public uint[] UIntA { get; }

    /// <summary>
    /// Gets the curve coefficient <c>b</c> as 32-bit words, ordered from least to most significant.
    /// </summary>
    public uint[] UIntB { get; }

    /// <summary>
    /// Gets the order of the base point as 32-bit words, ordered from least to most significant.
    /// </summary>
    public uint[] UIntOrder { get; }

    /// <summary>
    /// Determines whether a field element is zero.
    /// </summary>
    /// <param name="x">The field element to test.</param>
    /// <returns>A non-zero value if <paramref name="x"/> is zero; otherwise, 0.</returns>
    public abstract int ElementIsZero(ReadOnlySpan<uint> x);

    /// <summary>
    /// Squares a field element.
    /// </summary>
    /// <param name="x">The field element to square.</param>
    /// <param name="z">The span that receives the result.</param>
    public abstract void ElementSquare(ReadOnlySpan<uint> x, Span<uint> z);

    /// <summary>
    /// Adds two field elements.
    /// </summary>
    /// <param name="x">The first operand.</param>
    /// <param name="y">The second operand.</param>
    /// <param name="z">The span that receives the result.</param>
    public abstract void ElementAdd(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z);

    /// <summary>
    /// Multiplies two field elements.
    /// </summary>
    /// <param name="x">The first operand.</param>
    /// <param name="y">The second operand.</param>
    /// <param name="z">The span that receives the result.</param>
    public abstract void ElementMultiply(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z);

    /// <summary>
    /// Computes the square root of a field element.
    /// </summary>
    /// <param name="x">The field element whose square root is computed.</param>
    /// <param name="z">The span that receives the result.</param>
    /// <returns><see langword="true"/> if <paramref name="x"/> is a quadratic residue; otherwise, <see langword="false"/>.</returns>
    public abstract bool ElementSqrt(ReadOnlySpan<uint> x, Span<uint> z);

    /// <summary>
    /// Negates a field element.
    /// </summary>
    /// <param name="x">The field element to negate.</param>
    /// <param name="z">The span that receives the result.</param>
    public abstract void ElementNegate(ReadOnlySpan<uint> x, Span<uint> z);

    /// <summary>
    /// Determines whether a seed is usable as a private key.<br/>
    /// The seed must have the curve's byte length, be non-zero, be below the order of the base point,
    /// and have enough bit variation to rule out trivially weak values.
    /// </summary>
    /// <param name="seed">The big-endian seed to validate.</param>
    /// <returns><see langword="true"/> if the seed is valid; otherwise, <see langword="false"/>.</returns>
    public bool IsValidSeed(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != this.ByteLength)
        {
            return false;
        }

        if (IsZero(seed) || !IsBelow(seed, this.ByteOrder))
        {
            return false;
        }

        var weight = GetWeight(seed);
        if (weight < (this.BitLength >> 2))
        {
            return false;
        }

        return true;

        static bool IsZero(ReadOnlySpan<byte> value)
        {
            foreach (var x in value)
            {
                if (x != 0)
                {
                    return false;
                }
            }

            return true;
        }

        static bool IsBelow(ReadOnlySpan<byte> value, ReadOnlySpan<byte> target)
        {// Big-endian comparison: the first differing byte decides the result.
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != target[i])
                {
                    return value[i] < target[i];
                }
            }

            return false; // Equal values are not below the target.
        }

        static int GetWeight(ReadOnlySpan<byte> value)
        {
            var v = new BigInteger(value, true, true);
            var d = ((v << 1) + v) ^ v;

            var length = (d.GetByteCount(true) + (sizeof(ulong) - sizeof(byte))) / sizeof(ulong);
            var u = new ulong[length];
            d.TryWriteBytes(MemoryMarshal.AsBytes<ulong>(u.AsSpan()), out _, true, true);

            var sum = 0;
            foreach (var x in u)
            {
                sum += BitOperations.PopCount(x);
            }

            return sum;
        }
    }

    /// <summary>
    /// Compresses the y coordinate of a point to a single bit.
    /// </summary>
    /// <param name="y">The big-endian y coordinate.</param>
    /// <returns>The least significant bit of <paramref name="y"/>, or 0 if <paramref name="y"/> is empty.</returns>
    public uint CompressY(ReadOnlySpan<byte> y)
    {
        if (y.Length == 0)
        {
            return 0;
        }

        return (uint)y[y.Length - 1] & 1;
    }

    /// <summary>
    /// Recovers the y coordinate of a point from its x coordinate and the compressed sign bit.
    /// </summary>
    /// <param name="x">The big-endian x coordinate. Its length must be <see cref="ByteLength"/>.</param>
    /// <param name="y">The compressed y bit, as returned by <see cref="CompressY(ReadOnlySpan{byte})"/>.</param>
    /// <returns>The big-endian y coordinate, or <see langword="null"/> if the point is not on the curve.</returns>
    public byte[]? TryDecompressY(ReadOnlySpan<byte> x, uint y)
    {
        if (x.Length != this.ByteLength)
        {
            return null;
        }

        return this.DecompressPoint(y, x);
    }

    private byte[]? DecompressPoint(uint yTilde, ReadOnlySpan<byte> x1)
    {
        var length = x1.Length / 4;
        scoped Span<uint> x = stackalloc uint[length];
        for (var i = length - 1; i >= 0; i--)
        {
            var val = BitConverter.ToUInt32(x1);
            val = (val >> 16) | (val << 16);
            val = ((val & 0xFF00FF00U) >> 8) | ((val & 0x00FF00FFU) << 8);
            x[i] = val;

            x1 = x1.Slice(sizeof(uint));
        }

        scoped Span<uint> tmp = stackalloc uint[x.Length];
        scoped Span<uint> tmp2 = stackalloc uint[x.Length];

        this.ElementSquare(x, tmp);
        this.ElementAdd(tmp, this.UIntA, tmp2);
        this.ElementMultiply(tmp2, x, tmp);
        this.ElementAdd(tmp, this.UIntB, tmp2);

        if (!this.ElementSqrt(tmp2, tmp))
        {
            return null;
        }

        var y = new byte[length * 4];
        var span = y.AsSpan();
        scoped Span<uint> src;
        if ((tmp[0] & 1) != yTilde)
        {
            this.ElementNegate(tmp, tmp2);

            src = tmp2;
        }
        else
        {
            src = tmp;
        }

        for (var i = src.Length - 1; i >= 0; i--)
        {
            var val = src[i];
            val = (val >> 16) | (val << 16);
            val = ((val & 0xFF00FF00U) >> 8) | ((val & 0x00FF00FFU) << 8);

            BitConverter.TryWriteBytes(span, val);
            span = span.Slice(sizeof(uint));
        }

        return y;
    }
}
