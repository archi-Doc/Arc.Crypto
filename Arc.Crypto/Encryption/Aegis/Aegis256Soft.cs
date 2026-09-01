// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto;

[SkipLocalsInit]
internal static class Aegis256Soft
{
    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData, int tagSize)
    {
        Init(key, nonce, out var s0, out var s1, out var s2, out var s3, out var s4, out var s5);

        var adLength = associatedData.Length;
        var adFull = adLength & ~15;
        ref byte adRef = ref MemoryMarshal.GetReference(associatedData);
        for (nint i = 0; i < adFull; i += 16)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ReadBigEndian(ref Unsafe.Add(ref adRef, i)));
        }

        Span<byte> pad = stackalloc byte[16];
        if (adLength != adFull)
        {
            pad.Clear();
            associatedData[adFull..].CopyTo(pad);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ReadBigEndian(ref MemoryMarshal.GetReference(pad)));
        }

        var length = plaintext.Length;
        var full = length & ~15;
        ref byte source = ref MemoryMarshal.GetReference(plaintext);
        ref byte destination = ref MemoryMarshal.GetReference(ciphertext);
        for (nint i = 0; i < full; i += 16)
        {
            Enc(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref Unsafe.Add(ref destination, i), ref Unsafe.Add(ref source, i));
        }

        if (length != full)
        {
            pad.Clear();
            plaintext[full..].CopyTo(pad);
            ref byte padRef = ref MemoryMarshal.GetReference(pad);
            Enc(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref padRef, ref padRef);
            pad[..(length - full)].CopyTo(ciphertext[full..]);
            CryptographicOperations.ZeroMemory(pad);
        }

        if (tagSize > 0)
        {
            Finalize(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ciphertext[^tagSize..], (ulong)adLength, (ulong)length);
        }
    }

    internal static bool Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData, int tagSize)
    {
        Init(key, nonce, out var s0, out var s1, out var s2, out var s3, out var s4, out var s5);

        var adLength = associatedData.Length;
        var adFull = adLength & ~15;
        ref byte adRef = ref MemoryMarshal.GetReference(associatedData);
        for (nint i = 0; i < adFull; i += 16)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ReadBigEndian(ref Unsafe.Add(ref adRef, i)));
        }

        if (adLength != adFull)
        {
            Span<byte> pad = stackalloc byte[16];
            pad.Clear();
            associatedData[adFull..].CopyTo(pad);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ReadBigEndian(ref MemoryMarshal.GetReference(pad)));
            CryptographicOperations.ZeroMemory(pad);
        }

        var length = plaintext.Length;
        var full = length & ~15;
        ref byte source = ref MemoryMarshal.GetReference(ciphertext);
        ref byte destination = ref MemoryMarshal.GetReference(plaintext);
        for (nint i = 0; i < full; i += 16)
        {
            Dec(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref Unsafe.Add(ref destination, i), ref Unsafe.Add(ref source, i));
        }

        if (length != full)
        {
            DecPartial(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, plaintext[full..], ciphertext.Slice(full, length - full));
        }

        if (tagSize > 0)
        {
            Span<byte> tag = stackalloc byte[Aegis256.MaxTagSize];
            tag = tag[..tagSize];
            Finalize(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, tag, (ulong)adLength, (ulong)length);

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
    private static void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, out UInt128 s0, out UInt128 s1, out UInt128 s2, out UInt128 s3, out UInt128 s4, out UInt128 s5)
    {
        var c0 = BinaryPrimitives.ReadUInt128BigEndian(AES.C0);
        var c1 = BinaryPrimitives.ReadUInt128BigEndian(AES.C1);
        var k0 = BinaryPrimitives.ReadUInt128BigEndian(key[..16]);
        var k1 = BinaryPrimitives.ReadUInt128BigEndian(key[16..]);
        var n0 = BinaryPrimitives.ReadUInt128BigEndian(nonce[..16]);
        var n1 = BinaryPrimitives.ReadUInt128BigEndian(nonce[16..]);

        s0 = k0 ^ n0;
        s1 = k1 ^ n1;
        s2 = c1;
        s3 = c0;
        s4 = k0 ^ c0;
        s5 = k1 ^ c1;

        for (var i = 0; i < 4; i++)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, k0);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, k1);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, k0 ^ n0);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, k1 ^ n1);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Update(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, UInt128 message)
    {
        // Written in reverse order so that each line reads only not-yet-overwritten state, keeping a single temporary.
        var t = s5;
        s5 = AES.Encrypt(s4, s5);
        s4 = AES.Encrypt(s3, s4);
        s3 = AES.Encrypt(s2, s3);
        s2 = AES.Encrypt(s1, s2);
        s1 = AES.Encrypt(s0, s1);
        s0 = AES.Encrypt(t, s0 ^ message);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Enc(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, ref byte ciphertext, ref byte plaintext)
    {
        var z = s1 ^ s4 ^ s5 ^ (s2 & s3);
        var xi = ReadBigEndian(ref plaintext);
        WriteBigEndian(ref ciphertext, xi ^ z);
        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, xi);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Dec(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, ref byte plaintext, ref byte ciphertext)
    {
        var z = s1 ^ s4 ^ s5 ^ (s2 & s3);
        var xi = ReadBigEndian(ref ciphertext) ^ z;
        WriteBigEndian(ref plaintext, xi);
        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, xi);
    }

    private static void DecPartial(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        var z = s1 ^ s4 ^ s5 ^ (s2 & s3);

        Span<byte> pad = stackalloc byte[16];
        pad.Clear();
        ciphertext.CopyTo(pad);
        ref byte padRef = ref MemoryMarshal.GetReference(pad);
        var t = ReadBigEndian(ref padRef);
        WriteBigEndian(ref padRef, t ^ z);
        pad[..ciphertext.Length].CopyTo(plaintext);

        pad[ciphertext.Length..].Clear();
        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ReadBigEndian(ref padRef));
        CryptographicOperations.ZeroMemory(pad);
    }

    private static void Finalize(ref UInt128 s0, ref UInt128 s1, ref UInt128 s2, ref UInt128 s3, ref UInt128 s4, ref UInt128 s5, Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        var t = s3 ^ new UInt128(BinaryPrimitives.ReverseEndianness(associatedDataLength * 8), BinaryPrimitives.ReverseEndianness(plaintextLength * 8));

        for (var i = 0; i < 7; i++)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, t);
        }

        ref byte tagRef = ref MemoryMarshal.GetReference(tag);
        if (tag.Length == 16)
        {
            WriteBigEndian(ref tagRef, s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5);
        }
        else
        {
            WriteBigEndian(ref tagRef, s0 ^ s1 ^ s2);
            WriteBigEndian(ref Unsafe.Add(ref tagRef, 16), s3 ^ s4 ^ s5);
        }
    }
}
