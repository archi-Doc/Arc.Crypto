// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Arc.Crypto;

/*public class AesNi
{
    public const int KeySizeInBytes = 16;

    private readonly Vector128<byte>[] roundKeys;

    public AesNi(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        this.roundKeys = KeyExpansion(key);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public void EncryptCbc(Span<byte> data, Span<byte> iv)
    {
        var keys = this.roundKeys;
        var blocks = MemoryMarshal.Cast<byte, Vector128<byte>>(data);
        var iv_vec = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(iv));

        _ = keys[10]; // Avoid bounds check.
        for (var i = 0; i < blocks.Length; i++)
        {
            iv_vec = Sse2.Xor(iv_vec, blocks[i]);

            iv_vec = Sse2.Xor(iv_vec, keys[0]);
            iv_vec = Aes.Encrypt(iv_vec, keys[1]);
            iv_vec = Aes.Encrypt(iv_vec, keys[2]);
            iv_vec = Aes.Encrypt(iv_vec, keys[3]);
            iv_vec = Aes.Encrypt(iv_vec, keys[4]);
            iv_vec = Aes.Encrypt(iv_vec, keys[5]);
            iv_vec = Aes.Encrypt(iv_vec, keys[6]);
            iv_vec = Aes.Encrypt(iv_vec, keys[7]);
            iv_vec = Aes.Encrypt(iv_vec, keys[8]);
            iv_vec = Aes.Encrypt(iv_vec, keys[9]);
            iv_vec = Aes.EncryptLast(iv_vec, keys[10]);

            blocks[i] = iv_vec;
        }

        Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(iv), iv_vec);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public void DecryptCbc(Span<byte> data, Span<byte> iv)
    {
        var keys = this.roundKeys;
        var blocks = MemoryMarshal.Cast<byte, Vector128<byte>>(data);
        var iv_vec = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(iv));

        _ = keys[19]; // Avoid bounds check.
        for (int i = 0; i < blocks.Length; i++)
        {
            Vector128<byte> b = blocks[i];
            Vector128<byte> nextIv = b;

            b = Sse2.Xor(b, keys[10]);
            b = Aes.Decrypt(b, keys[19]);
            b = Aes.Decrypt(b, keys[18]);
            b = Aes.Decrypt(b, keys[17]);
            b = Aes.Decrypt(b, keys[16]);
            b = Aes.Decrypt(b, keys[15]);
            b = Aes.Decrypt(b, keys[14]);
            b = Aes.Decrypt(b, keys[13]);
            b = Aes.Decrypt(b, keys[12]);
            b = Aes.Decrypt(b, keys[11]);
            b = Aes.DecryptLast(b, keys[0]);

            b = Sse2.Xor(b, iv_vec);
            iv_vec = nextIv;
            blocks[i] = b;
        }

        Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(iv), iv_vec);
    }

    private static Vector128<byte>[] KeyExpansion(ReadOnlySpan<byte> key)
    {
        var keys = new Vector128<byte>[20];

        keys[0] = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(key));

        MakeRoundKey(keys, 1, 0x01);
        MakeRoundKey(keys, 2, 0x02);
        MakeRoundKey(keys, 3, 0x04);
        MakeRoundKey(keys, 4, 0x08);
        MakeRoundKey(keys, 5, 0x10);
        MakeRoundKey(keys, 6, 0x20);
        MakeRoundKey(keys, 7, 0x40);
        MakeRoundKey(keys, 8, 0x80);
        MakeRoundKey(keys, 9, 0x1b);
        MakeRoundKey(keys, 10, 0x36);

        for (int i = 1; i < 10; i++)
        {
            keys[10 + i] = Aes.InverseMixColumns(keys[i]);
        }

        return keys;
    }

    private static void MakeRoundKey(Vector128<byte>[] keys, int i, byte rcon)
    {
        Vector128<byte> s = keys[i - 1];
        Vector128<byte> t = keys[i - 1];

        t = Aes.KeygenAssist(t, rcon);
        t = Sse2.Shuffle(t.AsUInt32(), 0xFF).AsByte();

        s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 4));
        s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 8));

        keys[i] = Sse2.Xor(s, t);
    }
}*/
