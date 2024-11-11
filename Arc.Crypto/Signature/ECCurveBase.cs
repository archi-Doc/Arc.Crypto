// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto.EC;

public abstract class ECCurveBase
{
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

    public abstract string CurveName { get; }

    public int UIntLength { get; }

    public int ByteLength => this.UIntLength * sizeof(uint);

    public int BitLength => this.UIntLength * sizeof(uint) * 8;

    /*public BigInteger Q { get; }

    public BigInteger A { get; }

    public BigInteger B { get; }

    public BigInteger Order { get; }*/

    public byte[] ByteQ { get; }

    public byte[] ByteA { get; }

    public byte[] ByteB { get; }

    public byte[] ByteOrder { get; }

    public uint[] UIntQ { get; }

    public uint[] UIntA { get; }

    public uint[] UIntB { get; }

    public uint[] UIntOrder { get; }

    public abstract int ElementIsZero(ReadOnlySpan<uint> x);

    public abstract void ElementSquare(ReadOnlySpan<uint> x, Span<uint> z);

    public abstract void ElementAdd(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z);

    public abstract void ElementMultiply(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z);

    public abstract bool ElementSqrt(ReadOnlySpan<uint> x, Span<uint> z);

    public abstract void ElementNegate(ReadOnlySpan<uint> x, Span<uint> z);

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
        {
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] < target[i])
                {
                    return true;
                }
            }

            return false;
        }

        static int GetWeight(ReadOnlySpan<byte> value)
        {
            var v = new BigInteger(value, true, true);
            var d = ((v << 1) + v) ^ v;

            var length = (d.GetByteCount(true) + (sizeof(ulong) - sizeof(byte))) / sizeof(ulong);
            var u = new ulong[length];
            d.TryWriteBytes(MemoryMarshal.AsBytes<ulong>(u), out _, true, true);

            var sum = 0;
            foreach (var x in u)
            {
                sum += BitOperations.PopCount(x);
            }

            return sum;
        }
    }

    public uint CompressY(ReadOnlySpan<byte> y)
    {
        if (y.Length == 0)
        {
            return 0;
        }

        return (uint)y[y.Length - 1] & 1;
    }

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
