// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// Provides methods for encryption and decryption using the AEGIS-256 algorithm.
/// </summary>
/// <remarks>
/// Uses x86 AES-NI or ARMv8 AES instructions when available. When hardware AES is unavailable or disabled,
/// the portable fallback uses lookup tables and is not constant-time, so it may leak the key through cache-timing side channels.
/// </remarks>
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
    /// The size of the shorter (default) authentication tag in bytes.<br/>
    /// A tag size of zero, which disables authentication, is also accepted.
    /// </summary>
    public const int MinTagSize = 16;

    /// <summary>
    /// The maximum size of the authentication tag in bytes.
    /// </summary>
    public const int MaxTagSize = 32;

    /// <summary>
    /// Encrypts the specified plaintext using the AEGIS-256 algorithm and appends the authentication tag.<br/>
    /// In-place operation is supported when both spans start at the same address.
    /// An overlapping <paramref name="ciphertext"/> must not start after <paramref name="plaintext"/>.
    /// </summary>
    /// <param name="ciphertext">The buffer to receive the ciphertext followed by the tag.<br/>
    /// Its length must be the plaintext length plus <paramref name="tagSize"/>.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce32">The nonce (exactly 32 bytes). Never reuse a nonce with the same key.</param>
    /// <param name="key32">The key (exactly 32 bytes).</param>
    /// <param name="associatedData">The associated data to authenticate but not encrypt.</param>
    /// <param name="tagSize">The tag size: 16 or 32 bytes. Zero appends no tag and disables authentication and tamper detection.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="tagSize"/> is not 0, <see cref="MinTagSize"/>, or <see cref="MaxTagSize"/>,
    /// or when the lengths of <paramref name="ciphertext"/>, <paramref name="nonce32"/>, or <paramref name="key32"/> are invalid.
    /// </exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ciphertext"/> overlaps <paramref name="plaintext"/> and starts after it.</exception>
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce32, ReadOnlySpan<byte> key32, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize && tagSize != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be 0, {MinTagSize}, or {MaxTagSize}.");
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

        if (plaintext.Overlaps(ciphertext, out var offset) && offset > 0)
        {// Each block would overwrite plaintext that has not been read yet.
            throw new ArgumentException($"{nameof(ciphertext)} must not start after an overlapping {nameof(plaintext)}.", nameof(ciphertext));
        }

        if (Aegis256x86.IsSupported())
        {
            Aegis256x86.Encrypt(ciphertext, plaintext, nonce32, key32, associatedData, tagSize);
        }
        else if (Aegis256Arm.IsSupported())
        {
            Aegis256Arm.Encrypt(ciphertext, plaintext, nonce32, key32, associatedData, tagSize);
        }
        else
        {
            Aegis256Soft.Encrypt(ciphertext, plaintext, nonce32, key32, associatedData, tagSize);
        }
    }

    /// <summary>
    /// Decrypts the specified ciphertext using the AEGIS-256 algorithm and verifies its authentication tag.<br/>
    /// In-place operation is supported when both spans start at the same address; the ciphertext is then overwritten even if verification fails.
    /// An overlapping <paramref name="plaintext"/> must not start after <paramref name="ciphertext"/>.
    /// </summary>
    /// <param name="plaintext">The buffer to receive the plaintext.<br/>
    /// Its length must be the ciphertext length minus <paramref name="tagSize"/>.</param>
    /// <param name="ciphertext">The ciphertext followed by the tag.</param>
    /// <param name="nonce32">The nonce (exactly 32 bytes) used for encryption.</param>
    /// <param name="key32">The key (exactly 32 bytes) used for encryption.</param>
    /// <param name="associatedData">The associated data used for encryption.</param>
    /// <param name="tagSize">The tag size used for encryption: 16 or 32 bytes. Zero skips verification.</param>
    /// <returns>True on success; false on authentication failure, with the plaintext buffer cleared. With a zero tag size, returns true without verification.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="tagSize"/> is not 0, <see cref="MinTagSize"/>, or <see cref="MaxTagSize"/>,
    /// or when the lengths of <paramref name="ciphertext"/>, <paramref name="plaintext"/>, <paramref name="nonce32"/>, or <paramref name="key32"/> are invalid.
    /// </exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="plaintext"/> overlaps <paramref name="ciphertext"/> and starts after it.</exception>
    public static bool TryDecrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce32, ReadOnlySpan<byte> key32, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize && tagSize != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be 0, {MinTagSize}, or {MaxTagSize}.");
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

        if (ciphertext.Overlaps(plaintext, out var offset) && offset > 0)
        {// Each block would overwrite ciphertext that has not been read yet.
            throw new ArgumentException($"{nameof(plaintext)} must not start after an overlapping {nameof(ciphertext)}.", nameof(plaintext));
        }

        if (Aegis256x86.IsSupported())
        {
            return Aegis256x86.Decrypt(plaintext, ciphertext, nonce32, key32, associatedData, tagSize);
        }
        else if (Aegis256Arm.IsSupported())
        {
            return Aegis256Arm.Decrypt(plaintext, ciphertext, nonce32, key32, associatedData, tagSize);
        }
        else
        {
            return Aegis256Soft.Decrypt(plaintext, ciphertext, nonce32, key32, associatedData, tagSize);
        }
    }
}
