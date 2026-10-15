// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto.EC;

/// <summary>
/// Base class for short Weierstrass elliptic curves of the form <c>y² = x³ + ax + b</c> over a prime field.<br/>
/// It provides point compression and seed (private key) validation; the field arithmetic is supplied by derived classes.
/// </summary>
/// <remarks>
/// A field element is a span of <see cref="UIntLength"/> 32-bit words, least significant word first, holding a canonical value
/// below the field prime. The <c>Element*</c> methods require canonical operands (the result is unspecified otherwise),
/// write fully reduced results, and accept an output span that is the same span as an operand.
/// Byte encodings (coordinates, seeds and curve parameters) are big-endian.
/// </remarks>
public abstract class ECCurveBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ECCurveBase"/> class.
    /// </summary>
    /// <param name="uintLength">The number of 32-bit words in a field element; must be positive and small enough for <see cref="BitLength"/> to fit in an <see cref="int"/>.</param>
    /// <param name="hexQ">The field prime, as a big-endian hexadecimal string of exactly <paramref name="uintLength"/> * 8 digits.</param>
    /// <param name="hexA">The curve coefficient <c>a</c>, in the same format as <paramref name="hexQ"/>.</param>
    /// <param name="hexB">The curve coefficient <c>b</c>, in the same format as <paramref name="hexQ"/>.</param>
    /// <param name="hexOrder">The order of the base point, in the same format as <paramref name="hexQ"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="uintLength"/> is zero, negative, or greater than <see cref="int.MaxValue"/> / 32.</exception>
    /// <exception cref="ArgumentNullException">A hexadecimal string is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A hexadecimal string does not have exactly <paramref name="uintLength"/> * 8 digits.</exception>
    /// <exception cref="FormatException">A hexadecimal string contains a non-hexadecimal character.</exception>
    public ECCurveBase(int uintLength, string hexQ, string hexA, string hexB, string hexOrder)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(uintLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(uintLength, int.MaxValue / 32); // Keeps ByteLength, BitLength and the digit count from overflowing.
        this.UIntLength = uintLength;

        this.ByteQ = DecodeHex(hexQ, this.ByteLength, nameof(hexQ));
        // this.Q = new BigInteger(this.ByteQ, true, true);
        this.UIntQ = BytesToUInt(this.ByteQ);

        this.ByteA = DecodeHex(hexA, this.ByteLength, nameof(hexA));
        // this.A = new BigInteger(this.ByteA, true, true);
        this.UIntA = BytesToUInt(this.ByteA);

        this.ByteB = DecodeHex(hexB, this.ByteLength, nameof(hexB));
        // this.B = new BigInteger(this.ByteB, true, true);
        this.UIntB = BytesToUInt(this.ByteB);

        this.ByteOrder = DecodeHex(hexOrder, this.ByteLength, nameof(hexOrder));
        // this.Order = new BigInteger(this.ByteOrder, true, true);
        this.UIntOrder = BytesToUInt(this.ByteOrder);

        static byte[] DecodeHex(string hex, int byteLength, string paramName)
        {// Every parameter must fill a whole field element; the arithmetic assumes full-length arrays.
            ArgumentNullException.ThrowIfNull(hex, paramName);
            if (hex.Length != byteLength * 2)
            {
                throw new ArgumentException($"The value must have exactly {byteLength * 2} hexadecimal digits ({byteLength} bytes), but it has {hex.Length}.", paramName);
            }

            return Hex.FromStringToByteArray(hex);
        }

        uint[] BytesToUInt(ReadOnlySpan<byte> b)
        {
            var length = b.Length / 4;
            var x = new uint[length];
            for (var i = length - 1; i >= 0; i--)
            {
                x[i] = BinaryPrimitives.ReadUInt32BigEndian(b);
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
    /// Gets the field prime as big-endian bytes.<br/>
    /// The array is shared; do not modify it.
    /// </summary>
    public byte[] ByteQ { get; }

    /// <summary>
    /// Gets the curve coefficient <c>a</c> as big-endian bytes.<br/>
    /// The array is shared; do not modify it.
    /// </summary>
    public byte[] ByteA { get; }

    /// <summary>
    /// Gets the curve coefficient <c>b</c> as big-endian bytes.<br/>
    /// The array is shared; do not modify it.
    /// </summary>
    public byte[] ByteB { get; }

    /// <summary>
    /// Gets the order of the base point as big-endian bytes.<br/>
    /// The array is shared; do not modify it.
    /// </summary>
    public byte[] ByteOrder { get; }

    /// <summary>
    /// Gets the field prime as 32-bit words, ordered from least to most significant.<br/>
    /// The array is shared; do not modify it.
    /// </summary>
    public uint[] UIntQ { get; }

    /// <summary>
    /// Gets the curve coefficient <c>a</c> as 32-bit words, ordered from least to most significant.<br/>
    /// The array is shared; do not modify it.
    /// </summary>
    public uint[] UIntA { get; }

    /// <summary>
    /// Gets the curve coefficient <c>b</c> as 32-bit words, ordered from least to most significant.<br/>
    /// The array is shared; do not modify it.
    /// </summary>
    public uint[] UIntB { get; }

    /// <summary>
    /// Gets the order of the base point as 32-bit words, ordered from least to most significant.<br/>
    /// The array is shared; do not modify it.
    /// </summary>
    public uint[] UIntOrder { get; }

    /// <summary>
    /// Determines whether a field element is zero.
    /// </summary>
    /// <param name="x">The field element to test: <see cref="UIntLength"/> words, least significant first, below the field prime.</param>
    /// <returns>A non-zero value if <paramref name="x"/> is zero; otherwise, 0.</returns>
    public abstract int ElementIsZero(ReadOnlySpan<uint> x);

    /// <summary>
    /// Squares a field element.
    /// </summary>
    /// <param name="x">The field element to square: <see cref="UIntLength"/> words, least significant first, below the field prime.</param>
    /// <param name="z">The span that receives the reduced result. It may be the same span as <paramref name="x"/>.</param>
    public abstract void ElementSquare(ReadOnlySpan<uint> x, Span<uint> z);

    /// <summary>
    /// Adds two field elements.
    /// </summary>
    /// <param name="x">The first operand: <see cref="UIntLength"/> words, least significant first, below the field prime.</param>
    /// <param name="y">The second operand, in the same format as <paramref name="x"/>.</param>
    /// <param name="z">The span that receives the reduced result. It may be the same span as an operand.</param>
    public abstract void ElementAdd(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z);

    /// <summary>
    /// Multiplies two field elements.
    /// </summary>
    /// <param name="x">The first operand: <see cref="UIntLength"/> words, least significant first, below the field prime.</param>
    /// <param name="y">The second operand, in the same format as <paramref name="x"/>.</param>
    /// <param name="z">The span that receives the reduced result. It may be the same span as an operand.</param>
    public abstract void ElementMultiply(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z);

    /// <summary>
    /// Computes a square root of a field element.
    /// </summary>
    /// <param name="x">The field element: <see cref="UIntLength"/> words, least significant first, below the field prime.</param>
    /// <param name="z">The span that receives a square root of <paramref name="x"/>. It may be the same span as <paramref name="x"/>,
    /// and it is not written when the method returns <see langword="false"/>.</param>
    /// <returns><see langword="true"/> if <paramref name="x"/> is a square (zero or a quadratic residue); otherwise, <see langword="false"/>.</returns>
    public abstract bool ElementSqrt(ReadOnlySpan<uint> x, Span<uint> z);

    /// <summary>
    /// Negates a field element (the negation of zero is zero).
    /// </summary>
    /// <param name="x">The field element to negate: <see cref="UIntLength"/> words, least significant first, below the field prime.</param>
    /// <param name="z">The span that receives the reduced result. It may be the same span as <paramref name="x"/>.</param>
    public abstract void ElementNegate(ReadOnlySpan<uint> x, Span<uint> z);

    /// <summary>
    /// Determines whether a seed is usable as a private key.<br/>
    /// The seed must be <see cref="ByteLength"/> bytes long, non-zero, below the order of the base point,
    /// and have a non-adjacent form (NAF) weight of at least <see cref="BitLength"/> / 4, which rules out trivially weak values.
    /// </summary>
    /// <param name="seed">The big-endian seed to validate.</param>
    /// <returns><see langword="true"/> if the seed is valid; otherwise, <see langword="false"/>.</returns>
    public bool IsValidSeed(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != this.ByteLength)
        {
            return false;
        }

        // The range checks are branch-free over the secret seed bytes; only the outcome is revealed.
        if (IsZero(seed) | !IsBelow(seed, this.ByteOrder))
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
            var acc = 0;
            foreach (var x in value)
            {
                acc |= x;
            }

            return acc == 0;
        }

        static bool IsBelow(ReadOnlySpan<byte> value, ReadOnlySpan<byte> target)
        {// Big-endian comparison without early exit: compute value - target from the least significant byte and keep the final borrow.
            var borrow = 0;
            for (var i = value.Length - 1; i >= 0; i--)
            {
                var d = value[i] - target[i] - borrow;
                borrow = (d >> 31) & 1;
            }

            return borrow != 0; // A final borrow means value < target; equal values are not below the target.
        }

        static int GetWeight(ReadOnlySpan<byte> value)
        {
            // Count the set bits of (3 * value) XOR value, including the final carry.
            // Processing from the least significant byte avoids temporary big integers.
            var sum = 0;
            uint carry = 0;
            for (var i = value.Length - 1; i >= 0; i--)
            {
                uint product = ((uint)value[i] * 3) + carry;
                sum += BitOperations.PopCount((product ^ value[i]) & 0xFF);
                carry = product >> 8;
            }

            return sum + BitOperations.PopCount(carry);
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
    /// Recovers the y coordinate of a point from its x coordinate and the parity bit of y.
    /// </summary>
    /// <param name="x">The big-endian x coordinate.</param>
    /// <param name="yBit">The parity of y, as returned by <see cref="CompressY(ReadOnlySpan{byte})"/>. Only the least significant bit is used.</param>
    /// <returns>A new <see cref="ByteLength"/>-byte array holding the big-endian y coordinate, or <see langword="null"/> if <paramref name="x"/>
    /// is not <see cref="ByteLength"/> bytes long, is not below the field prime, or is not the x coordinate of a point on the curve.</returns>
    public byte[]? DecompressY(ReadOnlySpan<byte> x, uint yBit)
    {
        if (x.Length != this.ByteLength || x.SequenceCompareTo(this.ByteQ) >= 0)
        {
            return null;
        }

        return this.DecompressPoint(yBit, x);
    }

    private byte[]? DecompressPoint(uint yTilde, ReadOnlySpan<byte> x1)
    {
        yTilde &= 1; // Only the least significant bit is meaningful (see CompressY).

        var length = x1.Length / 4;
        scoped Span<uint> x = stackalloc uint[length];
        for (var i = length - 1; i >= 0; i--)
        {
            x[i] = BinaryPrimitives.ReadUInt32BigEndian(x1);
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
            BinaryPrimitives.WriteUInt32BigEndian(span, src[i]);
            span = span.Slice(sizeof(uint));
        }

        return y;
    }
}
