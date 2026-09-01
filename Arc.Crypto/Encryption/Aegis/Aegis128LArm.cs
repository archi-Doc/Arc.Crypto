// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.Arm.Aes;

namespace Arc.Crypto;

[SkipLocalsInit]
internal static class Aegis128LArm
{
    internal static bool IsSupported() => Aes.IsSupported;

    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData, int tagSize)
    {
        Init(key, nonce, out var s0, out var s1, out var s2, out var s3, out var s4, out var s5, out var s6, out var s7);

        var adLength = associatedData.Length;
        var adFull = adLength & ~31;
        ref byte adRef = ref MemoryMarshal.GetReference(associatedData);
        for (nint i = 0; i < adFull; i += 32)
        {
            var ad0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref adRef, i));
            var ad1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref adRef, i + 16));
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ad0, ad1);
        }

        Span<byte> pad = stackalloc byte[32];
        if (adLength != adFull)
        {
            pad.Clear();
            associatedData[adFull..].CopyTo(pad);
            ref byte padRef = ref MemoryMarshal.GetReference(pad);
            var ad0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref padRef);
            var ad1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref padRef, 16));
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ad0, ad1);
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
            var ad0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref adRef, i));
            var ad1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref adRef, i + 16));
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ad0, ad1);
        }

        if (adLength != adFull)
        {
            Span<byte> pad = stackalloc byte[32];
            pad.Clear();
            associatedData[adFull..].CopyTo(pad);
            ref byte padRef = ref MemoryMarshal.GetReference(pad);
            var ad0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref padRef);
            var ad1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref padRef, 16));
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ad0, ad1);
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

    /// <summary>
    /// Computes one AES encryption round (SubBytes, ShiftRows, MixColumns, AddRoundKey), equivalent to x86 AESENC.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> AesRound(Vector128<byte> value, Vector128<byte> roundKey)
        => Aes.MixColumns(Aes.Encrypt(value, Vector128<byte>.Zero)) ^ roundKey;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, out Vector128<byte> s0, out Vector128<byte> s1, out Vector128<byte> s2, out Vector128<byte> s3, out Vector128<byte> s4, out Vector128<byte> s5, out Vector128<byte> s6, out Vector128<byte> s7)
    {
        var c0 = Vector128.Create(AES.C0);
        var c1 = Vector128.Create(AES.C1);
        var k = Vector128.Create(key);
        var n = Vector128.Create(nonce);

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
    private static void Update(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, ref Vector128<byte> s6, ref Vector128<byte> s7, Vector128<byte> m0, Vector128<byte> m1)
    {
        // Written in reverse order so that each line reads only not-yet-overwritten state,
        // keeping a single temporary and minimizing register pressure (all eight AES rounds stay independent).
        var t = s7;
        s7 = AesRound(s6, s7);
        s6 = AesRound(s5, s6);
        s5 = AesRound(s4, s5);
        s4 = AesRound(s3, s4 ^ m1);
        s3 = AesRound(s2, s3);
        s2 = AesRound(s1, s2);
        s1 = AesRound(s0, s1);
        s0 = AesRound(t, s0 ^ m0);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Enc(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, ref Vector128<byte> s6, ref Vector128<byte> s7, ref byte ciphertext, ref byte plaintext)
    {
        var z0 = s6 ^ s1 ^ (s2 & s3);
        var z1 = s2 ^ s5 ^ (s6 & s7);

        var t0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref plaintext);
        var t1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref plaintext, 16));
        Unsafe.WriteUnaligned(ref ciphertext, t0 ^ z0);
        Unsafe.WriteUnaligned(ref Unsafe.Add(ref ciphertext, 16), t1 ^ z1);

        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, t0, t1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Dec(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, ref Vector128<byte> s6, ref Vector128<byte> s7, ref byte plaintext, ref byte ciphertext)
    {
        var z0 = s6 ^ s1 ^ (s2 & s3);
        var z1 = s2 ^ s5 ^ (s6 & s7);

        var t0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref ciphertext) ^ z0;
        var t1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref ciphertext, 16)) ^ z1;
        Unsafe.WriteUnaligned(ref plaintext, t0);
        Unsafe.WriteUnaligned(ref Unsafe.Add(ref plaintext, 16), t1);

        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, t0, t1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DecPartial(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, ref Vector128<byte> s6, ref Vector128<byte> s7, Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        var z0 = s6 ^ s1 ^ (s2 & s3);
        var z1 = s2 ^ s5 ^ (s6 & s7);

        Span<byte> pad = stackalloc byte[32];
        pad.Clear();
        ciphertext.CopyTo(pad);
        ref byte padRef = ref MemoryMarshal.GetReference(pad);
        var t0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref padRef);
        var t1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref padRef, 16));
        Unsafe.WriteUnaligned(ref padRef, t0 ^ z0);
        Unsafe.WriteUnaligned(ref Unsafe.Add(ref padRef, 16), t1 ^ z1);
        pad[..ciphertext.Length].CopyTo(plaintext);

        pad[ciphertext.Length..].Clear();
        var v0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref padRef);
        var v1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref padRef, 16));
        Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, v0, v1);
        CryptographicOperations.ZeroMemory(pad);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Finalize(ref Vector128<byte> s0, ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4, ref Vector128<byte> s5, ref Vector128<byte> s6, ref Vector128<byte> s7, Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        var t = s2 ^ Vector128.Create(associatedDataLength * 8, plaintextLength * 8).AsByte();

        for (var i = 0; i < 7; i++)
        {
            Update(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, t, t);
        }

        ref byte tagRef = ref MemoryMarshal.GetReference(tag);
        if (tag.Length == 16)
        {
            Unsafe.WriteUnaligned(ref tagRef, s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5 ^ s6);
        }
        else
        {
            Unsafe.WriteUnaligned(ref tagRef, s0 ^ s1 ^ s2 ^ s3);
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref tagRef, 16), s4 ^ s5 ^ s6 ^ s7);
        }
    }
}
