// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static System.Numerics.BitOperations;

#pragma warning disable SA1132 // Do not combine fields
#pragma warning disable SA1204
#pragma warning disable SA1310 // Field names should not contain underscore
#pragma warning disable SA1519 // Braces should not be omitted from multi-line child statement

namespace Arc.Crypto;

/// <summary>
/// An allocation-free, incremental 64-bit FarmHash.<br/>
/// Usage: <c>var farm = default(FarmHash);</c> then <c>farm.Append(data);</c> repeatedly and <c>var hash = farm.Finalize();</c>.<br/>
/// The result is identical to <see cref="Hash64(ReadOnlySpan{byte})"/> over the concatenated input.
/// Call <see cref="Initialize"/> to reuse the instance after <see cref="Finalize"/>.
/// </summary>
public unsafe ref struct FarmHash
{
    private const ulong K0 = 0xc3a5c85c97cb3127UL;
    private const ulong K1 = 0xb492b66fbe98f273UL;
    private const ulong K2 = 0x9ae16a3b2f90404fUL;

    // Precomputed streaming state for Seed0 = 81, Seed1 = 0 (farmhashuo).
    private const ulong X0 = 0x01529cba0ca458ffUL; // 81 * K2
    private const ulong Y0 = 113;                  // (0 * K2) + 113
    private const ulong Z0 = 0x7cb371d23f5eb1e0UL; // ShiftMix(Y0 * K2) * K2
    private const ulong U0 = 0x834c8e2dc0a14e71UL; // 81 - Z0

    private const int RawLimit = 256;              // up to this total size, the raw input is kept and hashed by the small-input algorithms.
    private const int BufferSize = RawLimit + 64;  // 320

    // Raw phase: buffer[0..position) holds the entire input so far (position <= 256).
    // Block phase: buffer[0..64) holds the previous 64 bytes, buffer[64..64+position) the pending tail (1 <= position <= 64).
    private fixed byte buffer[BufferSize];
    private int position;
    private bool blockPhase;

    private ulong x, y, z, v0, v1, w0, w1, u;

    /// <summary>
    /// Static function: Calculates a 64bit hash from the given data.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A 64bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(ReadOnlySpan<byte> input)
    {
        fixed (byte* p = input)
        {
            return Hash64(p, (uint)input.Length);
        }
    }

    /// <summary>
    /// Static function: Calculates a 64bit hash from the given string.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A 64bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(ReadOnlySpan<char> input) => Hash64(MemoryMarshal.AsBytes(input));

    /// <summary>
    /// Static function: Calculates a 64bit hash from the given string.
    /// </summary>
    /// <param name="str">The string containing the characters to calculates.</param>
    /// <returns>A 64bit hash.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Hash64(string str) => Hash64(MemoryMarshal.AsBytes(str.AsSpan()));

    /// <summary>
    /// Resets the state so the instance can be reused. Not required for a fresh <c>default(FarmHash)</c>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Initialize()
    {
        this.position = 0;
        this.blockPhase = false;
    }

    /// <summary>
    /// Appends data to the hash.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    public void Append(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty)
        {
            return;
        }

        fixed (byte* pin = input)
        fixed (byte* buf = this.buffer)
        {
            byte* src = pin;
            var len = input.Length;
            if (!this.blockPhase)
            {
                if (len <= RawLimit - this.position)
                {// keep raw input.
                    Buffer.MemoryCopy(src, buf + this.position, len, len);
                    this.position += len;
                    return;
                }

                // Transition to block processing: initialize state, catch up the buffered bytes.
                this.x = X0;
                this.y = Y0;
                this.z = Z0;
                this.v0 = 81;
                this.v1 = 0;
                this.w0 = 0;
                this.w1 = 0;
                this.u = U0;
                this.blockPhase = true;

                var c = BufferSize - this.position;
                if (len <= c)
                {// total 257..320 bytes, all in buffer. Process the first 4 blocks (a following byte is guaranteed).
                    Buffer.MemoryCopy(src, buf + this.position, len, len);
                    var tail = this.position + len - RawLimit; // 1..64
                    this.Rounds(buf, 4);
                    Buffer.MemoryCopy(buf + 192, buf, 64, 64);
                    Buffer.MemoryCopy(buf + RawLimit, buf + 64, tail, tail);
                    this.position = tail;
                    return;
                }

                // Fill the buffer completely (320 bytes), process its 5 blocks, then continue directly from the input.
                Buffer.MemoryCopy(src, buf + this.position, c, c);
                src += c;
                len -= c;
                this.Rounds(buf, 5);
                this.ProcessDirect(src, len, buf + RawLimit, buf);
                return;
            }

            // Block phase.
            var t = this.position;
            if (len <= 64 - t)
            {// still fits in the pending tail.
                Buffer.MemoryCopy(src, buf + 64 + t, len, len);
                this.position = t + len;
                return;
            }

            // Complete the pending block (a following byte is guaranteed) and process it.
            var fill = 64 - t;
            Buffer.MemoryCopy(src, buf + 64 + t, fill, fill);
            this.Rounds(buf + 64, 1);
            this.ProcessDirect(src + fill, len - fill, buf + 64, buf);
        }
    }

    /// <summary>
    /// Appends characters (as raw UTF-16 bytes) to the hash.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(ReadOnlySpan<char> input) => this.Append(MemoryMarshal.AsBytes(input));

    /// <summary>
    /// Finalizes the hash calculation.
    /// </summary>
    /// <returns>A 64bit hash, identical to <see cref="Hash64(ReadOnlySpan{byte})"/> over the concatenated input.</returns>
    public ulong Finalize()
    {
        fixed (byte* buf = this.buffer)
        {
            if (!this.blockPhase)
            {// small input: the raw bytes are still in the buffer.
                return Hash64(buf, (uint)this.position);
            }

            unchecked
            {// farmhashuo final mixing over the last 64 bytes, buffer[position..position + 64).
                byte* s = buf + this.position;
                var u = this.u * 9;
                var v1 = RotateRight(this.v1, 28);
                var v0 = RotateRight(this.v0, 20);
                var w0 = this.w0 + (ulong)(uint)(this.position - 1);
                u += this.y;
                var y = this.y + u;
                var x = RotateRight(y - this.x + v0 + Fetch64(s + 8), 37) * K2;
                y = RotateRight(y ^ v1 ^ Fetch64(s + 48), 42) * K2;
                x ^= this.w1 * 9;
                y += v0 + Fetch64(s + 40);
                var z = RotateRight(this.z + w0, 33) * K2;
                WeakHashLen32WithSeeds(s, v1 * K2, x + w0, out v0, out v1);
                WeakHashLen32WithSeeds(s + 32, z + this.w1, y + Fetch64(s + 16), out w0, out var w1);
                return H(HashLen16(v0 + x, w0 ^ y, K2) + z - u, H(v1 + y, w1 + z, K2, 30) ^ x, K2, 31);
            }
        }
    }

    /// <summary>
    /// Processes all complete 64byte blocks of the input except the final one, then stores the
    /// last-64-bytes window and the pending tail (1..64 bytes) into the buffer.
    /// </summary>
    private void ProcessDirect(byte* src, int len, byte* prev, byte* buf)
    {// len >= 1, prev = the 64 already-buffered bytes preceding src.
        var blocks = (nint)((uint)(len - 1) >> 6);
        byte* p = src;
        if (blocks > 0)
        {
            this.Rounds(p, blocks);
            p += blocks << 6;
            prev = p - 64;
        }

        var tail = (int)(len - (p - src)); // 1..64
        Buffer.MemoryCopy(prev, buf, 64, 64);
        Buffer.MemoryCopy(p, buf + 64, tail, tail);
        this.position = tail;
    }

    /// <summary>
    /// Processes the given number of consecutive 64byte blocks (farmhashuo main loop).
    /// </summary>
    private void Rounds(byte* s, nint blocks)
    {
        unchecked
        {
            ulong x = this.x, y = this.y, z = this.z, v0 = this.v0, v1 = this.v1, w0 = this.w0, w1 = this.w1, u = this.u;
            do
            {
                var a0 = Fetch64(s);
                var a1 = Fetch64(s + 8);
                var a2 = Fetch64(s + 16);
                var a3 = Fetch64(s + 24);
                var a4 = Fetch64(s + 32);
                var a5 = Fetch64(s + 40);
                var a6 = Fetch64(s + 48);
                var a7 = Fetch64(s + 56);
                x += a0 + a1;
                y += a2;
                z += a3;
                v0 += a4;
                v1 += a5 + a1;
                w0 += a6;
                w1 += a7;
                x = RotateRight(x, 26) * 9;
                y = RotateRight(y, 29);
                z *= K2;
                v0 = RotateRight(v0, 33);
                v1 = RotateRight(v1, 30);
                w0 = (w0 ^ x) * 9;
                z = RotateRight(z, 32) + w1;
                w1 += z;
                z *= 9;
                var t = u;
                u = y;
                y = t;
                z += a0 + a6;
                v0 += a2;
                v1 += a3;
                w0 += a4;
                w1 += a5 + a6;
                x += a1;
                y += a7 + v0;
                v0 += x - y;
                v1 += w0;
                w0 += v1;
                w1 += x - y;
                x += w1;
                w1 = RotateRight(w1, 34);
                t = u;
                u = z;
                z = t;
                s += 64;
            }
            while (--blocks > 0);

            this.x = x;
            this.y = y;
            this.z = z;
            this.v0 = v0;
            this.v1 = v1;
            this.w0 = w0;
            this.w1 = w1;
            this.u = u;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Fetch32(byte* p) => *(uint*)p;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Fetch64(byte* p) => *(ulong*)p;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ShiftMix(ulong val) => val ^ (val >> 47);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Swap(ref ulong x, ref ulong z)
    {
        var temp = z;
        z = x;
        x = temp;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen16(ulong u, ulong v, ulong mul)
    {
        unchecked
        {// Murmur-inspired hashing.
            var a = (u ^ v) * mul;
            a ^= a >> 47;
            var b = (v ^ a) * mul;
            b ^= b >> 47;
            return b * mul;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong H(ulong x, ulong y, ulong mul, int r)
    {
        unchecked
        {
            var a = (x ^ y) * mul;
            a ^= a >> 47;
            var b = (y ^ a) * mul;
            return RotateRight(b, r) * mul;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Hash64(byte* s, uint len)
    {
        if (len <= 16)
        {
            return HashLen0to16(s, len);
        }
        else if (len <= 32)
        {
            return HashLen17to32(s, len);
        }
        else if (len <= 64)
        {
            return HashLen33to64(s, len);
        }
        else if (len <= 96)
        {
            return HashLen65to96(s, len);
        }
        else if (len <= 256)
        {
            return Hash64NA(s, len);
        }

        return Hash64UO(s, len);
    }

    // 0-16 farmhashna.cc
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen0to16(byte* s, uint len)
    {
        unchecked
        {
            if (len >= 8)
            {
                var mul = K2 + (len * 2);
                var a = Fetch64(s) + K2;
                var b = Fetch64(s + len - 8);
                var c = (RotateRight(b, 37) * mul) + a;
                var d = (RotateRight(a, 25) + b) * mul;
                return HashLen16(c, d, mul);
            }
            else if (len >= 4)
            {
                var mul = K2 + (len * 2);
                ulong a = Fetch32(s);
                return HashLen16(len + (a << 3), Fetch32(s + len - 4), mul);
            }
            else if (len > 0)
            {
                var a = s[0];
                var b = s[len >> 1];
                var c = s[len - 1];
                var y = a + ((uint)b << 8);
                var z = len + ((uint)c << 2);
                return ShiftMix((y * K2) ^ (z * K0)) * K2;
            }

            return K2;
        }
    }

    // 17-32 farmhashna.cc
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen17to32(byte* s, uint len)
    {
        unchecked
        {
            var mul = K2 + (len * 2);
            var a = Fetch64(s) * K1;
            var b = Fetch64(s + 8);
            var c = Fetch64(s + len - 8) * mul;
            var d = Fetch64(s + len - 16) * K2;
            return HashLen16(RotateRight(a + b, 43) + RotateRight(c, 30) + d, a + RotateRight(b + K2, 18) + c, mul);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong H32(byte* s, uint len, ulong mul, ulong seed0 = 0, ulong seed1 = 0)
    {
        unchecked
        {
            var a = Fetch64(s) * K1;
            var b = Fetch64(s + 8);
            var c = Fetch64(s + len - 8) * mul;
            var d = Fetch64(s + len - 16) * K2;
            var u = RotateRight(a + b, 43) + RotateRight(c, 30) + d + seed0;
            var v = a + RotateRight(b + K2, 18) + c + seed1;
            a = ShiftMix((u ^ v) * mul);
            return ShiftMix((v ^ a) * mul);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen33to64(byte* s, uint len)
    {
        const ulong mul0 = K2 - 30;
        unchecked
        {
            var mul1 = K2 - 30 + (2 * len);
            var h0 = H32(s, 32, mul0);
            var h1 = H32(s + len - 32, 32, mul1);
            return ((h1 * mul1) + h0) * mul1;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong HashLen65to96(byte* s, uint len)
    {
        const ulong mul0 = K2 - 114;
        unchecked
        {
            var mul1 = K2 - 114 + (2 * len);
            var h0 = H32(s, 32, mul0);
            var h1 = H32(s + 32, 32, mul1);
            var h2 = H32(s + len - 32, 32, mul1, h0, h1);
            return ((h2 * 9) + (h0 >> 17) + (h1 >> 21)) * mul1;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WeakHashLen32WithSeeds(ulong w, ulong x, ulong y, ulong z, ulong a, ulong b, out ulong first, out ulong second)
    {
        unchecked
        {
            a += w;
            b = RotateRight(b + a + z, 21);
            var c = a;
            a += x;
            a += y;
            b += RotateRight(a, 44);
            first = a + z;
            second = b + c;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WeakHashLen32WithSeeds(byte* s, ulong a, ulong b, out ulong first, out ulong second)
        => WeakHashLen32WithSeeds(Fetch64(s), Fetch64(s + 8), Fetch64(s + 16), Fetch64(s + 24), a, b, out first, out second);

    private static ulong Hash64NA(byte* s, uint len)
    {
        const ulong seed = 81;
        unchecked
        {// For strings over 64 bytes we loop. Internal state consists of 56 bytes: v, w, x, y, and z.
            var x = seed;
            var y = (seed * K1) + 113;
            var z = ShiftMix((y * K2) + 113) * K2;
            ulong v0 = 0, v1 = 0, w0 = 0, w1 = 0;
            x = (x * K2) + Fetch64(s);

            // Set end so that after the loop we have 1 to 64 bytes left to process.
            byte* end = s + ((len - 1) / 64 * 64);
            byte* last64 = end + ((len - 1) & 63) - 63;
            do
            {
                x = RotateRight(x + y + v0 + Fetch64(s + 8), 37) * K1;
                y = RotateRight(y + v1 + Fetch64(s + 48), 42) * K1;
                x ^= w1;
                y += v0 + Fetch64(s + 40);
                z = RotateRight(z + w0, 33) * K1;
                WeakHashLen32WithSeeds(s, v1 * K1, x + w0, out v0, out v1);
                WeakHashLen32WithSeeds(s + 32, z + w1, y + Fetch64(s + 16), out w0, out w1);
                Swap(ref z, ref x);
                s += 64;
            }
            while (s != end);

            var mul = K1 + ((z & 0xff) << 1);

            // Make s point to the last 64 bytes of input.
            s = last64;
            w0 += (len - 1) & 63;
            v0 += w0;
            w0 += v0;
            x = RotateRight(x + y + v0 + Fetch64(s + 8), 37) * mul;
            y = RotateRight(y + v1 + Fetch64(s + 48), 42) * mul;
            x ^= w1 * 9;
            y += (v0 * 9) + Fetch64(s + 40);
            z = RotateRight(z + w0, 33) * mul;
            WeakHashLen32WithSeeds(s, v1 * mul, x + w0, out v0, out v1);
            WeakHashLen32WithSeeds(s + 32, z + w1, y + Fetch64(s + 16), out w0, out w1);
            Swap(ref z, ref x);
            return HashLen16(HashLen16(v0, w0, mul) + (ShiftMix(y) * K0) + z, HashLen16(v1, w1, mul) + x, mul);
        }
    }

    private static ulong Hash64UO(byte* s, uint len)
    {
        unchecked
        {// For strings over 64 bytes we loop. Internal state consists of 64 bytes: u, v, w, x, y, and z.
            var x = X0;
            var y = Y0;
            var z = Z0;
            ulong v0 = 81, v1 = 0, w0 = 0, w1 = 0;
            var u = U0;

            // Set end so that after the loop we have 1 to 64 bytes left to process.
            byte* end = s + ((len - 1) / 64 * 64);
            byte* last64 = end + ((len - 1) & 63) - 63;
            do
            {
                var a0 = Fetch64(s);
                var a1 = Fetch64(s + 8);
                var a2 = Fetch64(s + 16);
                var a3 = Fetch64(s + 24);
                var a4 = Fetch64(s + 32);
                var a5 = Fetch64(s + 40);
                var a6 = Fetch64(s + 48);
                var a7 = Fetch64(s + 56);
                x += a0 + a1;
                y += a2;
                z += a3;
                v0 += a4;
                v1 += a5 + a1;
                w0 += a6;
                w1 += a7;
                x = RotateRight(x, 26) * 9;
                y = RotateRight(y, 29);
                z *= K2;
                v0 = RotateRight(v0, 33);
                v1 = RotateRight(v1, 30);
                w0 = (w0 ^ x) * 9;
                z = RotateRight(z, 32) + w1;
                w1 += z;
                z *= 9;
                Swap(ref u, ref y);
                z += a0 + a6;
                v0 += a2;
                v1 += a3;
                w0 += a4;
                w1 += a5 + a6;
                x += a1;
                y += a7 + v0;
                v0 += x - y;
                v1 += w0;
                w0 += v1;
                w1 += x - y;
                x += w1;
                w1 = RotateRight(w1, 34);
                Swap(ref u, ref z);
                s += 64;
            }
            while (s != end);

            // Make s point to the last 64 bytes of input.
            s = last64;
            u *= 9;
            v1 = RotateRight(v1, 28);
            v0 = RotateRight(v0, 20);
            w0 += (len - 1) & 63;
            u += y;
            y += u;
            x = RotateRight(y - x + v0 + Fetch64(s + 8), 37) * K2;
            y = RotateRight(y ^ v1 ^ Fetch64(s + 48), 42) * K2;
            x ^= w1 * 9;
            y += v0 + Fetch64(s + 40);
            z = RotateRight(z + w0, 33) * K2;
            WeakHashLen32WithSeeds(s, v1 * K2, x + w0, out v0, out v1);
            WeakHashLen32WithSeeds(s + 32, z + w1, y + Fetch64(s + 16), out w0, out w1);
            return H(HashLen16(v0 + x, w0 ^ y, K2) + z - u, H(v1 + y, w1 + z, K2, 30) ^ x, K2, 31);
        }
    }
}
