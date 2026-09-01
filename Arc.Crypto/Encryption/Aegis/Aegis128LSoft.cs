// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto;

[SkipLocalsInit]
internal static class Aegis128LSoft
{
    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData, int tagSize)
    {
        Init(key, nonce, out var s0, out var s1, out var s2, out var s3, out var s4, out var s5, out var s6, out var s7);

        var adLength = associatedData.Length;
        var adFull = adLength & ~31;
        ref byte adRef = ref MemoryMarshal.GetReference(associatedData);
        for (nint i = 0; i < adFull; i += 32)
        {
            var ad0 = ReadBigEndian(ref Unsafe.Add(ref adRef, i));
            var ad1 = ReadBigEndian(ref Unsafe.Add(ref adRef, i + 16));
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ad0, ad1);
        }

        Span<byte> pad = stackalloc byte[32];
        if (adLength != adFull)
        {
            pad.Clear();
            associatedData[adFull..].CopyTo(pad);
            ref byte padRef = ref MemoryMarshal.GetReference(pad);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ReadBigEndian(ref padRef), ReadBigEndian(ref Unsafe.Add(ref padRef, 16)));
        }

        var length = plaintext.Length;
        var full = length & ~31;
        ref byte source = ref MemoryMarshal.GetReference(plaintext);
        ref byte destination = ref MemoryMarshal.GetReference(ciphertext);
        for (nint i = 0; i < full; i += 32)
        {
            Enc(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ref Unsafe.Add(ref destination, i), ref Unsafe.Add(ref source, i));
        }

        if (length != full)
        {
            pad.Clear();
            plaintext[full..].CopyTo(pad);
            ref byte padRef = ref MemoryMarshal.GetReference(pad);
            Enc(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ref padRef, ref padRef);
            pad[..(length - full)].CopyTo(ciphertext[full..]);
            CryptographicOperations.ZeroMemory(pad);
        }

        if (tagSize > 0)
        {
            Finalize(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ciphertext[^tagSize..], (ulong)adLength, (ulong)length);
        }
    }

    internal static bool Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData, int tagSize)
    {
        Init(key, nonce, out var s0, out var s1, out var s2, out var s3, out var s4, out var s5, out var s6, out var s7);

        var adLength = associatedData.Length;
        var adFull = adLength & ~31;
        ref byte adRef = ref MemoryMarshal.GetReference(associatedData);
        for (nint i = 0; i < adFull; i += 32)
        {
            var ad0 = ReadBigEndian(ref Unsafe.Add(ref adRef, i));
            var ad1 = ReadBigEndian(ref Unsafe.Add(ref adRef, i + 16));
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ad0, ad1);
        }

        if (adLength != adFull)
        {
            Span<byte> pad = stackalloc byte[32];
            pad.Clear();
            associatedData[adFull..].CopyTo(pad);
            ref byte padRef = ref MemoryMarshal.GetReference(pad);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ReadBigEndian(ref padRef), ReadBigEndian(ref Unsafe.Add(ref padRef, 16)));
            CryptographicOperations.ZeroMemory(pad);
        }

        var length = plaintext.Length;
        var full = length & ~31;
        ref byte source = ref MemoryMarshal.GetReference(ciphertext);
        ref byte destination = ref MemoryMarshal.GetReference(plaintext);
        for (nint i = 0; i < full; i += 32)
        {
            Dec(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ref Unsafe.Add(ref destination, i), ref Unsafe.Add(ref source, i));
        }

        if (length != full)
        {
            DecPartial(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, plaintext[full..], ciphertext.Slice(full, length - full));
        }

        if (tagSize > 0)
        {
            Span<byte> tag = stackalloc byte[Aegis128L.MaxTagSize];
            tag = tag[..tagSize];
            Finalize(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, tag, (ulong)adLength, (ulong)length);

            if (!CryptographicOperations.FixedTimeEquals(tag, ciphertext[^tagSize..]))
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(tag);
                return false;
            }
        }

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 ReadBigEndian(ref byte source)
    {
        var value = Unsafe.ReadUnaligned<UInt128>(ref source);
        return BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteBigEndian(ref byte destination, UInt128 value)
        => Unsafe.WriteUnaligned(ref destination, BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, out UInt128 s0, out UInt128 s1, out UInt128 s2, out UInt128 s3, out UInt128 s4, out UInt128 s5, out UInt128 s6, out UInt128 s7)
    {
        var c0 = BinaryPrimitives.ReadUInt128BigEndian(AES.C0);
        var c1 = BinaryPrimitives.ReadUInt128BigEndian(AES.C1);
        var k = BinaryPrimitives.ReadUInt128BigEndian(key);
        var n = BinaryPrimitives.ReadUInt128BigEndian(nonce);

        s0 = k ^ n;
        s1 = c1;
        s2 = c0;
        s3 = c1;
        s4 = k ^ n;
        s5 = k ^ c0;
        s6 = k ^ c1;
        s7 = k ^ c0;

        for (var i = 0; i < 10; i++)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, n, k);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Update(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, ref UInt128 s6, ref UInt128 s7, UInt128 m0, UInt128 m1)
    {
        // Written in reverse order so that each line reads only not-yet-overwritten state, keeping a single temporary.
        var t = s7;
        s7 = AES.Encrypt(s6, s7);
        s6 = AES.Encrypt(s5, s6);
        s5 = AES.Encrypt(s4, s5);
        s4 = AES.Encrypt(s3, s4 ^ m1);
        s3 = AES.Encrypt(s2, s3);
        s2 = AES.Encrypt(s1, s2);
        s1 = AES.Encrypt(s0, s1);
        s0 = AES.Encrypt(t, s0 ^ m0);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Enc(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, ref UInt128 s6, ref UInt128 s7, ref byte ciphertext, ref byte plaintext)
    {
        var z0 = s6 ^ s1 ^ (s2 & s3);
        var z1 = s2 ^ s5 ^ (s6 & s7);

        var t0 = ReadBigEndian(ref plaintext);
        var t1 = ReadBigEndian(ref Unsafe.Add(ref plaintext, 16));
        WriteBigEndian(ref ciphertext, t0 ^ z0);
        WriteBigEndian(ref Unsafe.Add(ref ciphertext, 16), t1 ^ z1);

        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, t0, t1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Dec(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, ref UInt128 s6, ref UInt128 s7, ref byte plaintext, ref byte ciphertext)
    {
        var z0 = s6 ^ s1 ^ (s2 & s3);
        var z1 = s2 ^ s5 ^ (s6 & s7);

        var t0 = ReadBigEndian(ref ciphertext) ^ z0;
        var t1 = ReadBigEndian(ref Unsafe.Add(ref ciphertext, 16)) ^ z1;
        WriteBigEndian(ref plaintext, t0);
        WriteBigEndian(ref Unsafe.Add(ref plaintext, 16), t1);

        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, t0, t1);
    }

    private static void DecPartial(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, ref UInt128 s6, ref UInt128 s7, Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        var z0 = s6 ^ s1 ^ (s2 & s3);
        var z1 = s2 ^ s5 ^ (s6 & s7);

        Span<byte> pad = stackalloc byte[32];
        pad.Clear();
        ciphertext.CopyTo(pad);
        ref byte padRef = ref MemoryMarshal.GetReference(pad);
        var t0 = ReadBigEndian(ref padRef);
        var t1 = ReadBigEndian(ref Unsafe.Add(ref padRef, 16));
        WriteBigEndian(ref padRef, t0 ^ z0);
        WriteBigEndian(ref Unsafe.Add(ref padRef, 16), t1 ^ z1);
        pad[..ciphertext.Length].CopyTo(plaintext);

        pad[ciphertext.Length..].Clear();
        var v0 = ReadBigEndian(ref padRef);
        var v1 = ReadBigEndian(ref Unsafe.Add(ref padRef, 16));
        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, v0, v1);
        CryptographicOperations.ZeroMemory(pad);
    }

    private static void Finalize(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, ref UInt128 s6, ref UInt128 s7, Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        var t = s2 ^ new UInt128(BinaryPrimitives.ReverseEndianness(associatedDataLength * 8), BinaryPrimitives.ReverseEndianness(plaintextLength * 8));

        for (var i = 0; i < 7; i++)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, t, t);
        }

        ref byte tagRef = ref MemoryMarshal.GetReference(tag);
        if (tag.Length == 16)
        {
            WriteBigEndian(ref tagRef, s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5 ^ s6);
        }
        else
        {
            WriteBigEndian(ref tagRef, s0 ^ s1 ^ s2 ^ s3);
            WriteBigEndian(ref Unsafe.Add(ref tagRef, 16), s4 ^ s5 ^ s6 ^ s7);
        }
    }
}
