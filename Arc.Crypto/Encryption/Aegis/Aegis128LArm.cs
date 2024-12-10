// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.Arm.Aes;

namespace Arc.Crypto;

#pragma warning disable SA1132 // Do not combine fields
#pragma warning disable SA1306 // Field names should begin with lower-case letter

[SkipLocalsInit]
internal ref struct Aegis128LArm
{
    private Vector128<byte> S0, S1, S2, S3, S4, S5, S6, S7;

    internal static bool IsSupported() => Aes.IsSupported;

    internal void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = Aegis128L.MinTagSize)
    {
        this.Init(key, nonce);

        int i = 0;
        Span<byte> pad = stackalloc byte[32];
        while (i + 32 <= associatedData.Length)
        {
            this.Absorb(associatedData.Slice(i, 32));
            i += 32;
        }

        if (associatedData.Length % 32 != 0)
        {
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            this.Absorb(pad);
        }

        i = 0;
        while (i + 32 <= plaintext.Length)
        {
            this.Enc(ciphertext.Slice(i, 32), plaintext.Slice(i, 32));
            i += 32;
        }

        if (plaintext.Length % 32 != 0)
        {
            Span<byte> tmp = stackalloc byte[32];
            pad.Clear();
            plaintext[i..].CopyTo(pad);
            this.Enc(tmp, pad);
            tmp[..(plaintext.Length % 32)].CopyTo(ciphertext[i..^tagSize]);
        }

        CryptographicOperations.ZeroMemory(pad);

        if (tagSize > 0)
        {
            this.Finalize(ciphertext[^tagSize..], (ulong)associatedData.Length, (ulong)plaintext.Length);
        }
    }

    internal bool Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = Aegis128L.MinTagSize)
    {
        this.Init(key, nonce);

        int i = 0;
        while (i + 32 <= associatedData.Length)
        {
            this.Absorb(associatedData.Slice(i, 32));
            i += 32;
        }

        if (associatedData.Length % 32 != 0)
        {
            Span<byte> pad = stackalloc byte[32];
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            this.Absorb(pad);
            CryptographicOperations.ZeroMemory(pad);
        }

        i = 0;
        while (i + 32 <= ciphertext.Length - tagSize)
        {
            this.Dec(plaintext.Slice(i, 32), ciphertext.Slice(i, 32));
            i += 32;
        }

        if ((ciphertext.Length - tagSize) % 32 != 0)
        {
            this.DecPartial(plaintext[i..], ciphertext[i..^tagSize]);
        }

        if (tagSize > 0)
        {
            Span<byte> tag = stackalloc byte[tagSize];
            this.Finalize(tag, (ulong)associatedData.Length, (ulong)plaintext.Length);

            if (!CryptographicOperations.FixedTimeEquals(tag, ciphertext[^tagSize..]))
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(tag);
                return false;
            }
        }

        return true;
    }

    private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        ReadOnlySpan<byte> c = stackalloc byte[]
        {
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
        };
        Vector128<byte> c0 = Vector128.Create(c[..16]);
        Vector128<byte> c1 = Vector128.Create(c[16..]);
        Vector128<byte> k = Vector128.Create(key);
        Vector128<byte> n = Vector128.Create(nonce);

        this.S0 = k ^ n;
        this.S1 = c1;
        this.S2 = c0;
        this.S3 = c1;
        this.S4 = k ^ n;
        this.S5 = k ^ c0;
        this.S6 = k ^ c1;
        this.S7 = k ^ c0;

        for (int i = 0; i < 10; i++)
        {
            this.Update(n, k);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Update(Vector128<byte> m0, Vector128<byte> m1)
    {
        var roundKey = this.S0 ^ m0;
        Vector128<byte> s0 = Aes.MixColumns(Aes.Encrypt(this.S7 ^ roundKey, roundKey)) ^ roundKey;

        Vector128<byte> s1 = Aes.MixColumns(Aes.Encrypt(this.S0 ^ this.S1, this.S1)) ^ this.S1;
        Vector128<byte> s2 = Aes.MixColumns(Aes.Encrypt(this.S1 ^ this.S2, this.S2)) ^ this.S2;
        Vector128<byte> s3 = Aes.MixColumns(Aes.Encrypt(this.S2 ^ this.S3, this.S3)) ^ this.S3;

        roundKey = this.S4 ^ m1;
        Vector128<byte> s4 = Aes.MixColumns(Aes.Encrypt(this.S3 ^ roundKey, roundKey)) ^ roundKey;

        Vector128<byte> s5 = Aes.MixColumns(Aes.Encrypt(this.S4 ^ this.S5, this.S5)) ^ this.S5;
        Vector128<byte> s6 = Aes.MixColumns(Aes.Encrypt(this.S5 ^ this.S6, this.S6)) ^ this.S6;
        Vector128<byte> s7 = Aes.MixColumns(Aes.Encrypt(this.S6 ^ this.S7, this.S7)) ^ this.S7;

        /*Vector128<byte> s0 = Aes.Encrypt(this.S7, this.S0 ^ m0);
        Vector128<byte> s1 = Aes.Encrypt(this.S0, this.S1);
        Vector128<byte> s2 = Aes.Encrypt(this.S1, this.S2);
        Vector128<byte> s3 = Aes.Encrypt(this.S2, this.S3);
        Vector128<byte> s4 = Aes.Encrypt(this.S3, this.S4 ^ m1);
        Vector128<byte> s5 = Aes.Encrypt(this.S4, this.S5);
        Vector128<byte> s6 = Aes.Encrypt(this.S5, this.S6);
        Vector128<byte> s7 = Aes.Encrypt(this.S6, this.S7);*/

        this.S0 = s0;
        this.S1 = s1;
        this.S2 = s2;
        this.S3 = s3;
        this.S4 = s4;
        this.S5 = s5;
        this.S6 = s6;
        this.S7 = s7;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Absorb(scoped ReadOnlySpan<byte> associatedData)
    {
        Vector128<byte> ad0 = Vector128.Create(associatedData[..16]);
        Vector128<byte> ad1 = Vector128.Create(associatedData[16..]);
        this.Update(ad0, ad1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Enc(scoped Span<byte> ciphertext, scoped ReadOnlySpan<byte> plaintext)
    {
        Vector128<byte> z0 = this.S6 ^ this.S1 ^ (this.S2 & this.S3);
        Vector128<byte> z1 = this.S2 ^ this.S5 ^ (this.S6 & this.S7);

        Vector128<byte> t0 = Vector128.Create(plaintext[..16]);
        Vector128<byte> t1 = Vector128.Create(plaintext[16..]);
        Vector128<byte> out0 = t0 ^ z0;
        Vector128<byte> out1 = t1 ^ z1;

        this.Update(t0, t1);
        out0.CopyTo(ciphertext[..16]);
        out1.CopyTo(ciphertext[16..]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z0 = this.S6 ^ this.S1 ^ (this.S2 & this.S3);
        Vector128<byte> z1 = this.S2 ^ this.S5 ^ (this.S6 & this.S7);

        Vector128<byte> t0 = Vector128.Create(ciphertext[..16]);
        Vector128<byte> t1 = Vector128.Create(ciphertext[16..]);
        Vector128<byte> out0 = t0 ^ z0;
        Vector128<byte> out1 = t1 ^ z1;

        this.Update(out0, out1);
        out0.CopyTo(plaintext[..16]);
        out1.CopyTo(plaintext[16..]);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z0 = this.S6 ^ this.S1 ^ (this.S2 & this.S3);
        Vector128<byte> z1 = this.S2 ^ this.S5 ^ (this.S6 & this.S7);

        Span<byte> pad = stackalloc byte[32];
        ciphertext.CopyTo(pad);
        Vector128<byte> t0 = Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(pad));
        Vector128<byte> t1 = Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(pad.Slice(16)));
        Vector128<byte> out0 = t0 ^ z0;
        Vector128<byte> out1 = t1 ^ z1;

        Span<byte> p = pad;
        out0.CopyTo(p[..16]);
        out1.CopyTo(p[16..]);
        p[..ciphertext.Length].CopyTo(plaintext);

        p[ciphertext.Length..].Clear();
        Vector128<byte> v0 = Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(pad));
        Vector128<byte> v1 = Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(pad.Slice(16)));
        this.Update(v0, v1);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private void Finalize(scoped Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(b[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(b[8..], plaintextLength * 8);

        Vector128<byte> t = this.S2 ^ Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(b)); // Vector128.Create(b);

        for (int i = 0; i < 7; i++)
        {
            this.Update(t, t);
        }

        if (tag.Length == 16)
        {
            Vector128<byte> a = this.S0 ^ this.S1 ^ this.S2 ^ this.S3 ^ this.S4 ^ this.S5 ^ this.S6;
            a.CopyTo(tag);
        }
        else
        {
            Vector128<byte> a1 = this.S0 ^ this.S1 ^ this.S2 ^ this.S3;
            Vector128<byte> a2 = this.S4 ^ this.S5 ^ this.S6 ^ this.S7;
            a1.CopyTo(tag[..16]);
            a2.CopyTo(tag[16..]);
        }
    }
}
