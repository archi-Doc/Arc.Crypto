// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

public static class Aegis256
{
    public const int KeySize = 32;
    public const int NonceSize = 32;
    public const int MinTagSize = 16;
    public const int MaxTagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize)
        {
            throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be equal to {MinTagSize} or {MaxTagSize}.");
        }

        if (ciphertext.Length != plaintext.Length + tagSize)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + tagSize} bytes long.");
        }

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long.");
        }

        if (key.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long.");
        }

        if (Aegis256x86.IsSupported())
        {
            Aegis256x86.Encrypt(ciphertext, plaintext, nonce, key, associatedData, tagSize);
        }
        else if (Aegis256Arm.IsSupported())
        {
            Aegis256Arm.Encrypt(ciphertext, plaintext, nonce, key, associatedData, tagSize);
        }
        else
        {
            Aegis256Soft.Encrypt(ciphertext, plaintext, nonce, key, associatedData, tagSize);
        }
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize)
        {
            throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be equal to {MinTagSize} or {MaxTagSize}.");
        }

        if (ciphertext.Length < tagSize)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {tagSize} bytes long.");
        }

        if (plaintext.Length != ciphertext.Length - tagSize)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - tagSize} bytes long.");
        }

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long.");
        }

        if (key.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long.");
        }

        if (Aegis256x86.IsSupported())
        {
            Aegis256x86.Decrypt(plaintext, ciphertext, nonce, key, associatedData, tagSize);
        }
        else if (Aegis256Arm.IsSupported())
        {
            Aegis256Arm.Decrypt(plaintext, ciphertext, nonce, key, associatedData, tagSize);
        }
        else
        {
            Aegis256Soft.Decrypt(plaintext, ciphertext, nonce, key, associatedData, tagSize);
        }
    }
}
