// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.Arm.Aes;

namespace Arc.Crypto;

[SkipLocalsInit]
internal static class Aegis256Arm
{
    internal static bool IsSupported() => Aes.IsSupported;

    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData, int tagSize)
    {
        Init(key, nonce, out var s0, out var s1, out var s2, out var s3, out var s4, out var s5);

        var adLength = associatedData.Length;
        var adFull = adLength & ~15;
        ref byte adRef = ref MemoryMarshal.GetReference(associatedData);
        for (nint i = 0; i < adFull; i += 16)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref adRef, i)));
        }

        Span<byte> pad = stackalloc byte[16];
        if (adLength != adFull)
        {
            pad.Clear();
            associatedData[adFull..].CopyTo(pad);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(pad)));
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
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref adRef, i)));
        }

        if (adLength != adFull)
        {
            Span<byte> pad = stackalloc byte[16];
            pad.Clear();
            associatedData[adFull..].CopyTo(pad);
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(pad)));
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

    /// <summary>
    /// Computes one AES encryption round (SubBytes, ShiftRows, MixColumns, AddRoundKey), equivalent to x86 AESENC.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> AesRound(Vector128<byte> value, Vector128<byte> roundKey)
        => Aes.MixColumns(Aes.Encrypt(value, Vector128<byte>.Zero)) ^ roundKey;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, out Vector128<byte> s0, out Vector128<byte> s1, out Vector128<byte> s2, out Vector128<byte> s3, out Vector128<byte> s4, out Vector128<byte> s5)
    {
        var c0 = Vector128.Create(AES.C0);
        var c1 = Vector128.Create(AES.C1);
        var k0 = Vector128.Create(key[..16]);
        var k1 = Vector128.Create(key[16..]);
        var n0 = Vector128.Create(nonce[..16]);
        var n1 = Vector128.Create(nonce[16..]);

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
    private static void Update(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, Vector128<byte> message)
    {
        // Written in reverse order so that each line reads only not-yet-overwritten state,
        // keeping a single temporary and minimizing register pressure (all six AES rounds stay independent).
        var t = s5;
        s5 = AesRound(s4, s5);
        s4 = AesRound(s3, s4);
        s3 = AesRound(s2, s3);
        s2 = AesRound(s1, s2);
        s1 = AesRound(s0, s1);
        s0 = AesRound(t, s0 ^ message);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Enc(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, ref byte ciphertext, ref byte plaintext)
    {
        var z = s1 ^ s4 ^ s5 ^ (s2 & s3);
        var xi = Unsafe.ReadUnaligned<Vector128<byte>>(ref plaintext);
        Unsafe.WriteUnaligned(ref ciphertext, xi ^ z);
        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, xi);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Dec(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, ref byte plaintext, ref byte ciphertext)
    {
        var z = s1 ^ s4 ^ s5 ^ (s2 & s3);
        var xi = Unsafe.ReadUnaligned<Vector128<byte>>(ref ciphertext) ^ z;
        Unsafe.WriteUnaligned(ref plaintext, xi);
        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, xi);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DecPartial(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        var z = s1 ^ s4 ^ s5 ^ (s2 & s3);

        Span<byte> pad = stackalloc byte[16];
        pad.Clear();
        ciphertext.CopyTo(pad);
        ref byte padRef = ref MemoryMarshal.GetReference(pad);
        var t = Unsafe.ReadUnaligned<Vector128<byte>>(ref padRef);
        Unsafe.WriteUnaligned(ref padRef, t ^ z);
        pad[..ciphertext.Length].CopyTo(plaintext);

        pad[ciphertext.Length..].Clear();
        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, Unsafe.ReadUnaligned<Vector128<byte>>(ref padRef));
        CryptographicOperations.ZeroMemory(pad);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Finalize(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        var t = s3 ^ Vector128.Create(associatedDataLength * 8, plaintextLength * 8).AsByte();

        for (var i = 0; i < 7; i++)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, t);
        }

        ref byte tagRef = ref MemoryMarshal.GetReference(tag);
        if (tag.Length == 16)
        {
            Unsafe.WriteUnaligned(ref tagRef, s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5);
        }
        else
        {
            Unsafe.WriteUnaligned(ref tagRef, s0 ^ s1 ^ s2);
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref tagRef, 16), s3 ^ s4 ^ s5);
        }
    }
}
