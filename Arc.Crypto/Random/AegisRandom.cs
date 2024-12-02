// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Arc.Crypto.Random;

// Xoshiro256StarStar + AEGIS-256
public class AegisRandom
{
    private const int RandomSize = 1024;
    private const int SuffixSize = Aegis256.KeySize + Aegis256.NonceSize + Aegis256.MinTagSize;
    private const int BufferSize = RandomSize + SuffixSize;

    #region FieldAndProperty

    private readonly Xoshiro256StarStar xo = new();
    private readonly byte[] buffer = new byte[RandomSize + SuffixSize];
    private readonly byte[] source = new byte[RandomSize + SuffixSize - Aegis256.MinTagSize];
    private int position;

    private int remaining => RandomSize - this.position;

    #endregion

    public AegisRandom()
    {
        this.FillBuffer();
    }

    public void NextBytes(Span<byte> buffer)
    {
        while (buffer.Length > 0)
        {
            if (this.remaining == 0)
            {
                this.FillBuffer();
            }

            var size = Math.Min(buffer.Length, this.remaining);
            this.buffer.AsSpan(this.position, size).CopyTo(buffer);
            buffer = buffer.Slice(size);
        }
    }

    private void FillBuffer()
    {
        Span<byte> suffix = stackalloc byte[SuffixSize];
        Span<byte> suffix2 = stackalloc byte[SuffixSize];
        this.buffer.AsSpan(RandomSize, SuffixSize).CopyTo(suffix);
        RandomNumberGenerator.Fill(suffix2);

        var s = MemoryMarshal.Cast<byte, ulong>(suffix);
        var s2 = MemoryMarshal.Cast<byte, ulong>(suffix2);
        for (var i = 0; i < s.Length; i++)
        {
            s[i] ^= s2[i];
        }

        this.xo.NextBytes(this.source);
        Aegis256.Encrypt(this.buffer, this.source, suffix.Slice(Aegis256.KeySize, Aegis256.NonceSize), suffix.Slice(0, Aegis256.KeySize));
        this.position = 0;
    }
}
