// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// Provides methods for encryption and decryption using the AEGIS-256L algorithm.
/// </summary>
public static class Aegis256
{
    /// <summary>
    /// The size of the key in bytes.
    /// </summary>
    public const int KeySize = 32;

    /// <summary>
    /// The size of the nonce in bytes.
    /// </summary>
    public const int NonceSize = 32;

    /// <summary>
    /// The minimum size of the authentication tag in bytes.
    /// </summary>
    public const int MinTagSize = 16;

    /// <summary>
    /// The maximum size of the authentication tag in bytes.
    /// </summary>
    public const int MaxTagSize = 32;

    /// <summary>
    /// Encrypts the specified plaintext using the Aegis-256 algorithm.
    /// </summary>
    /// <param name="ciphertext">The buffer to receive the ciphertext.<br/>
    /// Allocate a buffer with the size of the plaintext length plus the Tag size (16 bytes or 32 bytes).</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce32">The nonce (32 bytes) to use for encryption.</param>
    /// <param name="key32">The key (32 bytes) to use for encryption.</param>
    /// <param name="associatedData">The associated data to authenticate.</param>
    /// <param name="tagSize">The size of the authentication tag (16 or 32 bytes, or 0).</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="tagSize"/> is not equal to <see cref="MinTagSize"/> or <see cref="MaxTagSize"/>,
    /// or when the lengths of <paramref name="ciphertext"/>, <paramref name="nonce32"/>, or <paramref name="key32"/> are invalid.
    /// </exception>
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce32, ReadOnlySpan<byte> key32, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize && tagSize != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be equal to {MinTagSize} or {MaxTagSize}.");
        }

        if (ciphertext.Length != plaintext.Length + tagSize)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + tagSize} bytes long.");
        }

        if (nonce32.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce32), nonce32.Length, $"{nameof(nonce32)} must be {NonceSize} bytes long.");
        }

        if (key32.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key32), key32.Length, $"{nameof(key32)} must be {KeySize} bytes long.");
        }

        if (Aegis256x86.IsSupported())
        {
            var s = default(Aegis256x86);
            s.Encrypt(ciphertext, plaintext, nonce32, key32, associatedData, tagSize);
        }
        else if (Aegis256Arm.IsSupported())
        {
            var s = default(Aegis256Arm);
            s.Encrypt(ciphertext, plaintext, nonce32, key32, associatedData, tagSize);
        }
        else
        {
            var s = default(Aegis256Soft);
            s.Encrypt(ciphertext, plaintext, nonce32, key32, associatedData, tagSize);
        }
    }

    /// <summary>
    /// Decrypts the specified ciphertext using the Aegis-256 algorithm.
    /// </summary>
    /// <param name="plaintext">The buffer to receive the plaintext.<br/>
    /// Allocate a buffer with the size of the ciphertext length minus the Tag size (16 bytes or 32 bytes).</param>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="nonce32">The nonce (32 bytes) to use for decryption.</param>
    /// <param name="key32">The key (32 bytes) to use for decryption.</param>
    /// <param name="associatedData">The associated data to authenticate.</param>
    /// <param name="tagSize">The size of the authentication tag (16 or 32 bytes, or 0).</param>
    /// <returns><c>true</c> if decryption is successful; otherwise, <c>false</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="tagSize"/> is not equal to <see cref="MinTagSize"/> or <see cref="MaxTagSize"/>,
    /// or when the lengths of <paramref name="ciphertext"/>, <paramref name="plaintext"/>, <paramref name="nonce32"/>, or <paramref name="key32"/> are invalid.
    /// </exception>
    public static bool TryDecrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce32, ReadOnlySpan<byte> key32, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize && tagSize != 0)
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

        if (nonce32.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce32), nonce32.Length, $"{nameof(nonce32)} must be {NonceSize} bytes long.");
        }

        if (key32.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key32), key32.Length, $"{nameof(key32)} must be {KeySize} bytes long.");
        }

        if (Aegis256x86.IsSupported())
        {
            var s = default(Aegis256x86);
            return s.Decrypt(plaintext, ciphertext, nonce32, key32, associatedData, tagSize);
        }
        else if (Aegis256Arm.IsSupported())
        {
            var s = default(Aegis256Arm);
            return s.Decrypt(plaintext, ciphertext, nonce32, key32, associatedData, tagSize);
        }
        else
        {
            var s = default(Aegis256Soft);
            return s.Decrypt(plaintext, ciphertext, nonce32, key32, associatedData, tagSize);
        }
    }
}
