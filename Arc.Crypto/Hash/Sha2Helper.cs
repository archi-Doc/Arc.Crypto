// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Arc.Collections;

#pragma warning disable SA1124 // Do not use regions

namespace Arc.Crypto;

/// <summary>
/// Helper class for SHA2 functions.<br/>
/// This class is thread-safe and does not allocate heap memory.
/// </summary>
public static class Sha2Helper
{
    public static readonly ObjectPool<IncrementalHash> IncrementalSha256Pool = new(static () => IncrementalHash.CreateHash(HashAlgorithmName.SHA256));

    public static readonly ObjectPool<IncrementalHash> IncrementalSha384Pool = new(static () => IncrementalHash.CreateHash(HashAlgorithmName.SHA384));

    public static readonly ObjectPool<IncrementalHash> IncrementalSha512Pool = new(static () => IncrementalHash.CreateHash(HashAlgorithmName.SHA512));

    private static readonly ObjectPool<HashAlgorithm> Sha256 = new(static () => System.Security.Cryptography.SHA256.Create());

    private static readonly ObjectPool<HashAlgorithm> Sha384 = new(static () => System.Security.Cryptography.SHA384.Create());

    private static readonly ObjectPool<HashAlgorithm> Sha512 = new(static () => System.Security.Cryptography.SHA512.Create());

    public static void GetCryptoHash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length < 32)
        {
            throw new ArgumentOutOfRangeException(nameof(output));
        }

        LibsodiumInterops.crypto_hash(output, input, (ulong)input.Length);
    }

    /// <summary>
    /// Computes the SHA2-256 hash and returns the byte array (32 bytes).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <returns>The computed hash (32 bytes).</returns>
    public static byte[] Get256_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[32];
        var hashAlgorithm = Sha256.Get();
        hashAlgorithm.TryComputeHash(input, output, out _);
        Sha256.Return(hashAlgorithm);

        return output;
    }

    /// <summary>
    /// Computes the SHA2-256 hash and assign the result to the output (<see cref="byte"/>[32]).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <param name="output">The buffer to receive the hash value (<see cref="byte"/>[32]).</param>
    public static void Get256_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var hashAlgorithm = Sha256.Get();
        hashAlgorithm.TryComputeHash(input, output, out _);
        Sha256.Return(hashAlgorithm);
    }

    /// <summary>
    /// Computes the SHA2-256 hash and returns the hash (<see cref="ulong"/>).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <returns>The computed hash (<see cref="ulong"/>).</returns>
    public static (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) Get256_UInt64(ReadOnlySpan<byte> input)
    {
        Span<ulong> state = stackalloc ulong[4];

        var hashAlgorithm = Sha256.Get();
        hashAlgorithm.TryComputeHash(input, MemoryMarshal.Cast<ulong, byte>(state), out _);
        Sha256.Return(hashAlgorithm);
        // hashAlgorithm.TryComputeHash(input, MemoryMarshal.Cast<ulong, byte>(state), out _); // NOT thread-safe
        // System.Security.Cryptography.SHA256.TryHashData(input, MemoryMarshal.Cast<ulong, byte>(state), out _); // Slow

        return (state[0], state[1], state[2], state[3]);
    }

    /// <summary>
    /// Computes the SHA2-384 hash and returns the byte array (48 bytes).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <returns>The computed hash (48 bytes).</returns>
    public static byte[] Get384_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[48];
        var hashAlgorithm = Sha384.Get();
        hashAlgorithm.TryComputeHash(input, output, out _);
        Sha384.Return(hashAlgorithm);

        return output;
    }

    /// <summary>
    /// Computes the SHA2-384 hash and assign the result to the output (<see cref="byte"/>[48]).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <param name="output">The buffer to receive the hash value (<see cref="byte"/>[48]).</param>
    public static void Get384_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var hashAlgorithm = Sha384.Get();
        hashAlgorithm.TryComputeHash(input, output, out _);
        Sha384.Return(hashAlgorithm);
    }

    /// <summary>
    /// Computes the SHA2-384 hash and returns the hash (<see cref="ulong"/>).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <returns>The computed hash (<see cref="ulong"/>).</returns>
    public static (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3, ulong Hash4, ulong Hash5) Get384_UInt64(ReadOnlySpan<byte> input)
    {
        Span<ulong> state = stackalloc ulong[6];

        var hashAlgorithm = Sha384.Get();
        hashAlgorithm.TryComputeHash(input, MemoryMarshal.Cast<ulong, byte>(state), out _);
        Sha384.Return(hashAlgorithm);

        return (state[0], state[1], state[2], state[3], state[4], state[5]);
    }

    /// <summary>
    /// Computes the SHA2-512 hash and returns the byte array (64 bytes).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <returns>The computed hash (64 bytes).</returns>
    public static byte[] Get512_ByteArray(ReadOnlySpan<byte> input)
    {
        var output = new byte[64];
        var hashAlgorithm = Sha512.Get();
        hashAlgorithm.TryComputeHash(input, output, out _);
        Sha512.Return(hashAlgorithm);

        return output;
    }

    /// <summary>
    /// Computes the SHA2-512 hash and assign the result to the output (<see cref="byte"/>[64]).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <param name="output">The buffer to receive the hash value (<see cref="byte"/>[64]).</param>
    public static void Get512_Span(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var hashAlgorithm = Sha512.Get();
        hashAlgorithm.TryComputeHash(input, output, out _);
        Sha512.Return(hashAlgorithm);
    }

    /// <summary>
    /// Computes the SHA2-512 hash and returns the hash (<see cref="ulong"/>).<br/>
    /// Thread-safe and it does not allocate heap memory.
    /// </summary>
    /// <param name="input">The input to compute the hash for.</param>
    /// <returns>The computed hash (<see cref="ulong"/>).</returns>
    public static (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3, ulong Hash4, ulong Hash5, ulong Hash6, ulong Hash7) Get512_UInt64(ReadOnlySpan<byte> input)
    {
        Span<ulong> state = stackalloc ulong[8];

        var hashAlgorithm = Sha512.Get();
        hashAlgorithm.TryComputeHash(input, MemoryMarshal.Cast<ulong, byte>(state), out _);
        Sha512.Return(hashAlgorithm);

        return (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
    }
}

/*
/// <summary>
/// Represents a managed implementation of SHA2.
/// </summary>
public unsafe ref struct Sha2StateStruct
{
    public const int BufferLength = 64;

    private static readonly uint[] K = new uint[64]
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    public Sha2StateStruct(Span<uint> buffer)
    {
        this.buffer = buffer;
        this.Hash0 = 0x6a09e667;
        this.Hash1 = 0xbb67ae85;
        this.Hash2 = 0x3c6ef372;
        this.Hash3 = 0xa54ff53a;
        this.Hash4 = 0x510e527f;
        this.Hash5 = 0x9b05688c;
        this.Hash6 = 0x1f83d9ab;
        this.Hash7 = 0x5be0cd19;
    }

    #region FieldAndProperty

    public uint Hash0;
    public uint Hash1;
    public uint Hash2;
    public uint Hash3;
    public uint Hash4;
    public uint Hash5;
    public uint Hash6;
    public uint Hash7;

    private readonly Span<uint> buffer;

    #endregion

    public void Process(ReadOnlySpan<byte> input)
    {
        var bits = (ulong)input.Length * 8;
        while (input.Length >= 64)
        {
            this.ProcessBlock(input);
            input = input.Slice(64);
        }

        Span<byte> span = stackalloc byte[64];
        var b = span;

        // input.Length 0 - 63 + 0x80(1) + 0xN(N) + ulong(8)
        if (input.Length <= 55)
        {// input, 0x80, 0xN, ulong(8)
            var n = 64 - input.Length - 9;
            input.CopyTo(b);
            b = b.Slice(input.Length);
            b[0] = 0x80;
            b = b.Slice(1 + n);
            BitConverter.TryWriteBytes(b, bits);

            this.ProcessBlock(span);
        }
        else
        {
            // 1:input, 0x80, 0xN
            var n = 64 - input.Length - 1;
            input.CopyTo(b);
            b = b.Slice(input.Length);
            b[0] = 0x80;
            this.ProcessBlock(span);

            // 2:0xM, ulong(8)
            span.Clear();
            b = span.Slice(64 - 8);
            BitConverter.TryWriteBytes(b, bits);
            this.ProcessBlock(span);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Ro0(uint x) => BitOperations.RotateRight(x, 7) ^ BitOperations.RotateRight(x, 18) ^ (x >> 3);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Ro1(uint x) => BitOperations.RotateRight(x, 17) ^ BitOperations.RotateRight(x, 19) ^ (x >> 10);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Ch(uint x, uint y, uint z) => (x & y) ^ (~x & z);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Maj(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Parity(uint x, uint y, uint z) => x ^ y ^ z;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Sig0(uint x) => BitOperations.RotateRight(x, 2) ^ BitOperations.RotateRight(x, 13) ^ BitOperations.RotateRight(x, 22);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Sig1(uint x) => BitOperations.RotateRight(x, 6) ^ BitOperations.RotateRight(x, 11) ^ BitOperations.RotateRight(x, 25);

    private void ProcessBlock(scoped ReadOnlySpan<byte> b64)
    {
        fixed (uint* u = this.buffer)
        {
            fixed (void* source = b64)
            {
                Buffer.MemoryCopy(source, u, 64, 64);
            }

            for (var i = 16; i < BufferLength; i++)
            {
                u[i] = Ro1(u[i - 2]) + u[i - 7] + Ro0(u[i - 15]) + u[i - 16];
            }

            var a = this.Hash0;
            var b = this.Hash1;
            var c = this.Hash2;
            var d = this.Hash3;
            var e = this.Hash4;
            var f = this.Hash5;
            var g = this.Hash6;
            var h = this.Hash7;

            for (var i = 0; i < BufferLength - 7; i += 8)
            {
                h += u[i + 0] + K[i + 0] + Ch(e, f, g) + Sig1(e);
                d += h;
                h += Maj(a, b, c) + Sig0(a);

                g += u[i + 1] + K[i + 1] + Ch(d, e, f) + Sig1(d);
                c += g;
                g += Maj(h, a, b) + Sig0(h);

                f += u[i + 2] + K[i + 2] + Ch(c, d, e) + Sig1(c);
                b += f;
                f += Maj(g, h, a) + Sig0(g);

                e += u[i + 3] + K[i + 3] + Ch(b, c, d) + Sig1(b);
                a += e;
                e += Maj(f, g, h) + Sig0(f);

                d += u[i + 4] + K[i + 4] + Ch(a, b, c) + Sig1(a);
                h += d;
                d += Maj(e, f, g) + Sig0(e);

                c += u[i + 5] + K[i + 5] + Ch(h, a, b) + Sig1(h);
                g += c;
                c += Maj(d, e, f) + Sig0(d);

                b += u[i + 6] + K[i + 6] + Ch(g, h, a) + Sig1(g);
                f += b;
                b += Maj(c, d, e) + Sig0(c);

                a += u[i + 7] + K[i + 7] + Ch(f, g, h) + Sig1(f);
                e += a;
                a += Maj(b, c, d) + Sig0(b);
            }

            this.Hash0 += a;
            this.Hash1 += b;
            this.Hash2 += c;
            this.Hash3 += d;
            this.Hash4 += e;
            this.Hash5 += f;
            this.Hash6 += g;
            this.Hash7 += h;
        }
    }
}*/
