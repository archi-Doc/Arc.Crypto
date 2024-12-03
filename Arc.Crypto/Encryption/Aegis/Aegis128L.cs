// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// Provides methods for encryption and decryption using the AEGIS-128L algorithm.
/// </summary>
public static class Aegis128L
{
    /// <summary>
    /// The size of the key in bytes.
    /// </summary>
    public const int KeySize = 16;

    /// <summary>
    /// The size of the nonce in bytes.
    /// </summary>
    public const int NonceSize = 16;

    /// <summary>
    /// The minimum size of the authentication tag in bytes.
    /// </summary>
    public const int MinTagSize = 16;

    /// <summary>
    /// The maximum size of the authentication tag in bytes.
    /// </summary>
    public const int MaxTagSize = 32;

    /// <summary>
    /// Encrypts the specified plaintext using the Aegis-128L algorithm.
    /// </summary>
    /// <param name="ciphertext">The buffer to receive the ciphertext.<br/>
    /// Allocate a buffer with the size of the plaintext length plus the Tag size (16 bytes or 32 bytes).</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce16">The nonce (16 bytes) to use for encryption.</param>
    /// <param name="key16">The key (16 bytes) to use for encryption.</param>
    /// <param name="associatedData">The associated data to authenticate.</param>
    /// <param name="tagSize">The size of the authentication tag (16 or 32 bytes, or 0).</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="tagSize"/> is not equal to <see cref="MinTagSize"/> or <see cref="MaxTagSize"/>,
    /// or when the lengths of <paramref name="ciphertext"/>, <paramref name="nonce16"/>, or <paramref name="key16"/> are invalid.
    /// </exception>
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce16, ReadOnlySpan<byte> key16, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize && tagSize != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be equal to {MinTagSize} or {MaxTagSize}.");
        }

        if (ciphertext.Length != plaintext.Length + tagSize)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + tagSize} bytes long.");
        }

        if (nonce16.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce16), nonce16.Length, $"{nameof(nonce16)} must be {NonceSize} bytes long.");
        }

        if (key16.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key16), key16.Length, $"{nameof(key16)} must be {KeySize} bytes long.");
        }

        if (Aegis128Lx86.IsSupported())
        {
            Aegis128Lx86.Encrypt(ciphertext, plaintext, nonce16, key16, associatedData, tagSize);
        }
        else if (Aegis128LArm.IsSupported())
        {
            Aegis128LArm.Encrypt(ciphertext, plaintext, nonce16, key16, associatedData, tagSize);
        }
        else
        {
            Aegis128LSoft.Encrypt(ciphertext, plaintext, nonce16, key16, associatedData, tagSize);
        }
    }

    /// <summary>
    /// Decrypts the specified ciphertext using the Aegis-128L algorithm.
    /// </summary>
    /// <param name="plaintext">The buffer to receive the plaintext.<br/>
    /// Allocate a buffer with the size of the ciphertext length minus the Tag size (16 bytes or 32 bytes).</param>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="nonce16">The nonce (16 bytes) to use for decryption.</param>
    /// <param name="key16">The key (16 bytes) to use for decryption.</param>
    /// <param name="associatedData">The associated data to authenticate.</param>
    /// <param name="tagSize">The size of the authentication tag (16 or 32 bytes, or 0).</param>
    /// <returns><c>true</c> if decryption is successful; otherwise, <c>false</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="tagSize"/> is not equal to <see cref="MinTagSize"/> or <see cref="MaxTagSize"/>,
    /// or when the lengths of <paramref name="ciphertext"/>, <paramref name="plaintext"/>, <paramref name="nonce16"/>, or <paramref name="key16"/> are invalid.
    /// </exception>
    public static bool TryDecrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce16, ReadOnlySpan<byte> key16, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
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

        if (nonce16.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce16), nonce16.Length, $"{nameof(nonce16)} must be {NonceSize} bytes long.");
        }

        if (key16.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key16), key16.Length, $"{nameof(key16)} must be {KeySize} bytes long.");
        }

        if (Aegis128Lx86.IsSupported())
        {
            return Aegis128Lx86.Decrypt(plaintext, ciphertext, nonce16, key16, associatedData, tagSize);
        }
        else if (Aegis128LArm.IsSupported())
        {
            return Aegis128LArm.Decrypt(plaintext, ciphertext, nonce16, key16, associatedData, tagSize);
        }
        else
        {
            return Aegis128LSoft.Decrypt(plaintext, ciphertext, nonce16, key16, associatedData, tagSize);
        }
    }
}
