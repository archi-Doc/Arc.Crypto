// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

#pragma warning disable SA1204 // Static elements should appear before instance elements
#pragma warning disable SA1519

public unsafe ref struct FarmHash2
{
    private const ulong K0 = 0xc3a5c85c97cb3127UL;
    private const ulong K1 = 0xb492b66fbe98f273UL;
    private const ulong K2 = 0x9ae16a3b2f90404fUL;

    private const int SmallBufferSize = 256;
    private const int BlockSize = 64;
    private const int TailOffset = 64;

    // <= 256 bytes:
    //   [0..bufferLength] contains the complete input.
    //
    // > 256 bytes:
    //   [0..64]   contains the pending block.
    //   [64..128] contains the last 64 bytes.
    private fixed byte buffer[SmallBufferSize];

    private int bufferLength;
    private bool isLong;

    private ulong x;
    private ulong y;
    private ulong z;
    private ulong vFirst;
    private ulong vSecond;
    private ulong wFirst;
    private ulong wSecond;
    private ulong u;
    private ulong mul;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public FarmHash2()
    {
        Unsafe.SkipInit(out this);
        this.bufferLength = 0;
        this.isLong = false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(ReadOnlySpan<byte> input)
    {
        fixed (byte* p = input)
        {
            return Hash64(p, (uint)input.Length);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(ReadOnlySpan<char> input)
        => Hash64(MemoryMarshal.AsBytes(input));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(string input)
        => Hash64(input.AsSpan());

    public void Append(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty)
        {
            return;
        }

        fixed (byte* dst = this.buffer)
        fixed (byte* src = input)
        {
            if (this.isLong)
            {
                this.AppendLong(src, input.Length, dst);
                return;
            }

            int remaining = SmallBufferSize - this.bufferLength;
            if (input.Length <= remaining)
            {
                Buffer.MemoryCopy(src, dst + this.bufferLength, remaining, input.Length);
                this.bufferLength += input.Length;
                return;
            }

            if (remaining != 0)
            {
                Buffer.MemoryCopy(src, dst + this.bufferLength, remaining, remaining);
            }

            this.InitializeLong();

            this.HashRound(dst);
            this.HashRound(dst + 64);
            this.HashRound(dst + 128);
            this.HashRound(dst + 192);

            // Preserve the final 64 bytes of the first 256 bytes.
            Buffer.MemoryCopy(dst + 192, dst + TailOffset, BlockSize, BlockSize);

            this.isLong = true;
            this.bufferLength = 0;

            this.AppendLong(src + remaining, input.Length - remaining, dst);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(ReadOnlySpan<char> input)
        => this.Append(MemoryMarshal.AsBytes(input));

    /// <summary>
    /// Finalizes the hash computation and returns the 64-bit hash value.
    /// </summary>
    /// <returns>A 64-bit unsigned integer representing the FarmHash hash value of all appended data.</returns>
    /// <remarks>
    /// This method completes the hash computation. After calling this method, the <see cref="FarmHash2"/> instance
    /// should not be used again. Do not append more data or call this method again afterward.
    /// The method handles both short inputs (≤256 bytes) and long inputs (&gt;256 bytes) differently
    /// to optimize performance.
    /// </remarks>
    public ulong Finalize()
    {
        fixed (byte* p = this.buffer)
        {
            if (!this.isLong)
            {
                return Hash64(p, (uint)this.bufferLength);
            }

            return this.FinalizeLong(p + TailOffset, (uint)(this.bufferLength - 1));
        }
    }

    private void AppendLong(byte* input, int length, byte* buffer)
    {
        byte* originalInput = input;
        int originalLength = length;
        int pending = this.bufferLength;

        if (pending != 0)
        {
            int fill = BlockSize - pending;

            if (length <= fill)
            {
                Buffer.MemoryCopy(input, buffer + pending, fill, length);
                this.bufferLength = pending + length;
                UpdateTail(buffer + TailOffset, originalInput, originalLength);
                return;
            }

            if (fill != 0)
            {
                Buffer.MemoryCopy(input, buffer + pending, fill, fill);
            }

            this.HashRound(buffer);

            input += fill;
            length -= fill;
        }

        while (length > BlockSize)
        {
            this.HashRound(input);
            input += BlockSize;
            length -= BlockSize;
        }

        Buffer.MemoryCopy(input, buffer, BlockSize, length);
        this.bufferLength = length;

        UpdateTail(buffer + TailOffset, originalInput, originalLength);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void UpdateTail(byte* tail, byte* input, int length)
    {
        if (length >= BlockSize)
        {
            Buffer.MemoryCopy(input + length - BlockSize, tail, BlockSize, BlockSize);
            return;
        }

        int preserved = BlockSize - length;

        Buffer.MemoryCopy(tail + length, tail, preserved, preserved);
        Buffer.MemoryCopy(input, tail + preserved, length, length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void InitializeLong()
    {
        unchecked
        {
            this.x = 81;
            this.y = 113;
            this.z = ShiftMix(this.y * K2) * K2;
            this.vFirst = 81;
            this.vSecond = 0;
            this.wFirst = 0;
            this.wSecond = 0;
            this.u = this.x - this.z;
            this.x *= K2;
            this.mul = K2 + (this.u & 0x82);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Fetch32(byte* p)
        => *(uint*)p;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Fetch64(byte* p)
        => *(ulong*)p;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Rotate64(ulong value, int shift)
        => (value >> shift) | (value << (64 - shift));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ShiftMix(ulong value)
        => value ^ (value >> 47);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Swap(ref ulong x, ref ulong y)
    {
        ulong temp = x;
        x = y;
        y = temp;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen16(ulong u, ulong v, ulong mul)
    {
        unchecked
        {
            ulong a = (u ^ v) * mul;
            a ^= a >> 47;

            ulong b = (v ^ a) * mul;
            b ^= b >> 47;
            b *= mul;

            return b;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Hash64(byte* s, uint len)
    {
        if (len <= 32)
        {
            return len <= 16
                ? HashLen0to16(s, len)
                : HashLen17to32(s, len);
        }

        if (len <= 96)
        {
            return len <= 64
                ? HashLen33to64(s, len)
                : HashLen65to96(s, len);
        }

        return len <= 256
            ? Hash64NA(s, len)
            : Hash64UO(s, len);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen0to16(byte* s, uint len)
    {
        unchecked
        {
            if (len >= 8)
            {
                ulong mul = K2 + (len * 2);
                ulong a = Fetch64(s) + K2;
                ulong b = Fetch64(s + len - 8);
                ulong c = (Rotate64(b, 37) * mul) + a;
                ulong d = (Rotate64(a, 25) + b) * mul;

                return HashLen16(c, d, mul);
            }

            if (len >= 4)
            {
                ulong mul = K2 + (len * 2);
                ulong a = Fetch32(s);

                return HashLen16(
                    len + (a << 3),
                    Fetch32(s + len - 4),
                    mul);
            }

            if (len != 0)
            {
                uint a = s[0];
                uint b = s[len >> 1];
                uint c = s[len - 1];
                uint y = a + (b << 8);
                uint z = len + (c << 2);

                return ShiftMix((y * K2) ^ (z * K0)) * K2;
            }

            return K2;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen17to32(byte* s, uint len)
    {
        unchecked
        {
            ulong mul = K2 + (len * 2);
            ulong a = Fetch64(s) * K1;
            ulong b = Fetch64(s + 8);
            ulong c = Fetch64(s + len - 8) * mul;
            ulong d = Fetch64(s + len - 16) * K2;

            return HashLen16(
                Rotate64(a + b, 43) + Rotate64(c, 30) + d,
                a + Rotate64(b + K2, 18) + c,
                mul);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong H32(byte* s, uint len, ulong mul, ulong seed0 = 0, ulong seed1 = 0)
    {
        unchecked
        {
            ulong a = Fetch64(s) * K1;
            ulong b = Fetch64(s + 8);
            ulong c = Fetch64(s + len - 8) * mul;
            ulong d = Fetch64(s + len - 16) * K2;
            ulong u = Rotate64(a + b, 43) + Rotate64(c, 30) + d + seed0;
            ulong v = a + Rotate64(b + K2, 18) + c + seed1;

            a = ShiftMix((u ^ v) * mul);
            b = ShiftMix((v ^ a) * mul);

            return b;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen33to64(byte* s, uint len)
    {
        const ulong Mul0 = K2 - 30;

        unchecked
        {
            ulong mul = Mul0 + (2 * len);
            ulong h0 = H32(s, 32, Mul0);
            ulong h1 = H32(s + len - 32, 32, mul);

            return ((h1 * mul) + h0) * mul;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen65to96(byte* s, uint len)
    {
        const ulong Mul0 = K2 - 114;

        unchecked
        {
            ulong mul = Mul0 + (2 * len);
            ulong h0 = H32(s, 32, Mul0);
            ulong h1 = H32(s + 32, 32, mul);
            ulong h2 = H32(s + len - 32, 32, mul, h0, h1);

            return ((h2 * 9) + (h0 >> 17) + (h1 >> 21)) * mul;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WeakHashLen32WithSeeds(
        ulong w,
        ulong x,
        ulong y,
        ulong z,
        ulong a,
        ulong b,
        out ulong first,
        out ulong second)
    {
        unchecked
        {
            a += w;
            b = Rotate64(b + a + z, 21);

            ulong c = a;

            a += x + y;
            b += Rotate64(a, 44);

            first = a + z;
            second = b + c;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WeakHashLen32WithSeeds(byte* s, ulong a, ulong b, out ulong first, out ulong second)
    {
        WeakHashLen32WithSeeds(
            Fetch64(s),
            Fetch64(s + 8),
            Fetch64(s + 16),
            Fetch64(s + 24),
            a,
            b,
            out first,
            out second);
    }

    private static ulong Hash64NA(byte* s, uint len)
    {
        unchecked
        {
            ulong x = 81;
            ulong y = (81 * K1) + 113;
            ulong z = ShiftMix((y * K2) + 113) * K2;
            ulong vFirst = 0;
            ulong vSecond = 0;
            ulong wFirst = 0;
            ulong wSecond = 0;

            x = (x * K2) + Fetch64(s);

            byte* end = s + (((len - 1) / 64) * 64);
            byte* last64 = end + ((len - 1) & 63) - 63;

            do
            {
                x = Rotate64(x + y + vFirst + Fetch64(s + 8), 37) * K1;
                y = Rotate64(y + vSecond + Fetch64(s + 48), 42) * K1;
                x ^= wSecond;
                y += vFirst + Fetch64(s + 40);
                z = Rotate64(z + wFirst, 33) * K1;

                WeakHashLen32WithSeeds(s, vSecond * K1, x + wFirst, out vFirst, out vSecond);
                WeakHashLen32WithSeeds(s + 32, z + wSecond, y + Fetch64(s + 16), out wFirst, out wSecond);

                Swap(ref z, ref x);
                s += 64;
            }
            while (s != end);

            ulong mul = K1 + ((z & 0xff) << 1);

            s = last64;
            wFirst += (len - 1) & 63;
            vFirst += wFirst;
            wFirst += vFirst;

            x = Rotate64(x + y + vFirst + Fetch64(s + 8), 37) * mul;
            y = Rotate64(y + vSecond + Fetch64(s + 48), 42) * mul;
            x ^= wSecond * 9;
            y += (vFirst * 9) + Fetch64(s + 40);
            z = Rotate64(z + wFirst, 33) * mul;

            WeakHashLen32WithSeeds(s, vSecond * mul, x + wFirst, out vFirst, out vSecond);
            WeakHashLen32WithSeeds(s + 32, z + wSecond, y + Fetch64(s + 16), out wFirst, out wSecond);

            Swap(ref z, ref x);

            return HashLen16(
                HashLen16(vFirst, wFirst, mul) + (ShiftMix(y) * K0) + z,
                HashLen16(vSecond, wSecond, mul) + x,
                mul);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong H(ulong x, ulong y, ulong mul, int r)
    {
        unchecked
        {
            ulong a = (x ^ y) * mul;
            a ^= a >> 47;

            ulong b = (y ^ a) * mul;

            return Rotate64(b, r) * mul;
        }
    }

    private static ulong Hash64UO(byte* s, uint len)
    {
        unchecked
        {
            ulong x = 81;
            ulong y = 113;
            ulong z = ShiftMix(y * K2) * K2;
            ulong vFirst = 81;
            ulong vSecond = 0;
            ulong wFirst = 0;
            ulong wSecond = 0;
            ulong u = x - z;

            x *= K2;

            ulong mul = K2 + (u & 0x82);

            byte* end = s + (((len - 1) / 64) * 64);
            byte* last64 = end + ((len - 1) & 63) - 63;

            do
            {
                ulong a0 = Fetch64(s);
                ulong a1 = Fetch64(s + 8);
                ulong a2 = Fetch64(s + 16);
                ulong a3 = Fetch64(s + 24);
                ulong a4 = Fetch64(s + 32);
                ulong a5 = Fetch64(s + 40);
                ulong a6 = Fetch64(s + 48);
                ulong a7 = Fetch64(s + 56);

                x += a0 + a1;
                y += a2;
                z += a3;
                vFirst += a4;
                vSecond += a5 + a1;
                wFirst += a6;
                wSecond += a7;

                x = Rotate64(x, 26);
                x *= 9;
                y = Rotate64(y, 29);
                z *= mul;
                vFirst = Rotate64(vFirst, 33);
                vSecond = Rotate64(vSecond, 30);
                wFirst ^= x;
                wFirst *= 9;
                z = Rotate64(z, 32);
                z += wSecond;
                wSecond += z;
                z *= 9;

                Swap(ref u, ref y);

                z += a0 + a6;
                vFirst += a2;
                vSecond += a3;
                wFirst += a4;
                wSecond += a5 + a6;
                x += a1;
                y += a7;

                y += vFirst;
                vFirst += x - y;
                vSecond += wFirst;
                wFirst += vSecond;
                wSecond += x - y;
                x += wSecond;
                wSecond = Rotate64(wSecond, 34);

                Swap(ref u, ref z);

                s += 64;
            }
            while (s != end);

            s = last64;

            u *= 9;
            vSecond = Rotate64(vSecond, 28);
            vFirst = Rotate64(vFirst, 20);
            wFirst += (len - 1) & 63;
            u += y;
            y += u;

            x = Rotate64(y - x + vFirst + Fetch64(s + 8), 37) * mul;
            y = Rotate64(y ^ vSecond ^ Fetch64(s + 48), 42) * mul;
            x ^= wSecond * 9;
            y += vFirst + Fetch64(s + 40);
            z = Rotate64(z + wFirst, 33) * mul;

            WeakHashLen32WithSeeds(s, vSecond * mul, x + wFirst, out vFirst, out vSecond);
            WeakHashLen32WithSeeds(s + 32, z + wSecond, y + Fetch64(s + 16), out wFirst, out wSecond);

            return H(
                HashLen16(vFirst + x, wFirst ^ y, mul) + z - u,
                H(vSecond + y, wSecond + z, K2, 30) ^ x,
                K2,
                31);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void HashRound(byte* s)
    {
        unchecked
        {
            ulong a0 = Fetch64(s);
            ulong a1 = Fetch64(s + 8);
            ulong a2 = Fetch64(s + 16);
            ulong a3 = Fetch64(s + 24);
            ulong a4 = Fetch64(s + 32);
            ulong a5 = Fetch64(s + 40);
            ulong a6 = Fetch64(s + 48);
            ulong a7 = Fetch64(s + 56);

            this.x += a0 + a1;
            this.y += a2;
            this.z += a3;
            this.vFirst += a4;
            this.vSecond += a5 + a1;
            this.wFirst += a6;
            this.wSecond += a7;

            this.x = Rotate64(this.x, 26);
            this.x *= 9;
            this.y = Rotate64(this.y, 29);
            this.z *= this.mul;
            this.vFirst = Rotate64(this.vFirst, 33);
            this.vSecond = Rotate64(this.vSecond, 30);
            this.wFirst ^= this.x;
            this.wFirst *= 9;
            this.z = Rotate64(this.z, 32);
            this.z += this.wSecond;
            this.wSecond += this.z;
            this.z *= 9;

            Swap(ref this.u, ref this.y);

            this.z += a0 + a6;
            this.vFirst += a2;
            this.vSecond += a3;
            this.wFirst += a4;
            this.wSecond += a5 + a6;
            this.x += a1;
            this.y += a7;

            this.y += this.vFirst;
            this.vFirst += this.x - this.y;
            this.vSecond += this.wFirst;
            this.wFirst += this.vSecond;
            this.wSecond += this.x - this.y;
            this.x += this.wSecond;
            this.wSecond = Rotate64(this.wSecond, 34);

            Swap(ref this.u, ref this.z);
        }
    }

    private ulong FinalizeLong(byte* s, uint remainder)
    {
        unchecked
        {
            this.u *= 9;
            this.vSecond = Rotate64(this.vSecond, 28);
            this.vFirst = Rotate64(this.vFirst, 20);
            this.wFirst += remainder;
            this.u += this.y;
            this.y += this.u;

            this.x = Rotate64(this.y - this.x + this.vFirst + Fetch64(s + 8), 37) * this.mul;
            this.y = Rotate64(this.y ^ this.vSecond ^ Fetch64(s + 48), 42) * this.mul;
            this.x ^= this.wSecond * 9;
            this.y += this.vFirst + Fetch64(s + 40);
            this.z = Rotate64(this.z + this.wFirst, 33) * this.mul;

            WeakHashLen32WithSeeds(
                s,
                this.vSecond * this.mul,
                this.x + this.wFirst,
                out this.vFirst,
                out this.vSecond);

            WeakHashLen32WithSeeds(
                s + 32,
                this.z + this.wSecond,
                this.y + Fetch64(s + 16),
                out this.wFirst,
                out this.wSecond);

            return H(
                HashLen16(this.vFirst + this.x, this.wFirst ^ this.y, this.mul) + this.z - this.u,
                H(this.vSecond + this.y, this.wSecond + this.z, K2, 30) ^ this.x,
                K2,
                31);
        }
    }
}
