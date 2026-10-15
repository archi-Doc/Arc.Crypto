// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// Provides methods for encryption and decryption using the AEGIS-128L algorithm.
/// </summary>
/// <remarks>
/// Uses x86 AES-NI or ARMv8 AES instructions when available. When hardware AES is unavailable or disabled,
/// the portable fallback uses lookup tables and is not constant-time, so it may leak the key through cache-timing side channels.
/// </remarks>
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
    /// The size of the shorter (default) authentication tag in bytes.<br/>
    /// A tag size of zero, which disables authentication, is also accepted.
    /// </summary>
    public const int MinTagSize = 16;

    /// <summary>
    /// The maximum size of the authentication tag in bytes.
    /// </summary>
    public const int MaxTagSize = 32;

    /// <summary>
    /// Encrypts the specified plaintext using the AEGIS-128L algorithm and appends the authentication tag.<br/>
    /// In-place operation is supported when both spans start at the same address.
    /// An overlapping <paramref name="ciphertext"/> must not start after <paramref name="plaintext"/>.
    /// </summary>
    /// <param name="ciphertext">The buffer to receive the ciphertext followed by the tag.<br/>
    /// Its length must be the plaintext length plus <paramref name="tagSize"/>.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce16">The nonce (exactly 16 bytes). Never reuse a nonce with the same key.</param>
    /// <param name="key16">The key (exactly 16 bytes).</param>
    /// <param name="associatedData">The associated data to authenticate but not encrypt.</param>
    /// <param name="tagSize">The tag size: 16 or 32 bytes. Zero appends no tag and disables authentication and tamper detection.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="tagSize"/> is not 0, <see cref="MinTagSize"/>, or <see cref="MaxTagSize"/>,
    /// or when the lengths of <paramref name="ciphertext"/>, <paramref name="nonce16"/>, or <paramref name="key16"/> are invalid.
    /// </exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ciphertext"/> overlaps <paramref name="plaintext"/> and starts after it.</exception>
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce16, ReadOnlySpan<byte> key16, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize && tagSize != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be 0, {MinTagSize}, or {MaxTagSize}.");
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

        if (plaintext.Overlaps(ciphertext, out var offset) && offset > 0)
        {// Each block would overwrite plaintext that has not been read yet.
            throw new ArgumentException($"{nameof(ciphertext)} must not start after an overlapping {nameof(plaintext)}.", nameof(ciphertext));
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
    /// Decrypts the specified ciphertext using the AEGIS-128L algorithm and verifies its authentication tag.<br/>
    /// In-place operation is supported when both spans start at the same address; the ciphertext is then overwritten even if verification fails.
    /// An overlapping <paramref name="plaintext"/> must not start after <paramref name="ciphertext"/>.
    /// </summary>
    /// <param name="plaintext">The buffer to receive the plaintext.<br/>
    /// Its length must be the ciphertext length minus <paramref name="tagSize"/>.</param>
    /// <param name="ciphertext">The ciphertext followed by the tag.</param>
    /// <param name="nonce16">The nonce (exactly 16 bytes) used for encryption.</param>
    /// <param name="key16">The key (exactly 16 bytes) used for encryption.</param>
    /// <param name="associatedData">The associated data used for encryption.</param>
    /// <param name="tagSize">The tag size used for encryption: 16 or 32 bytes. Zero skips verification.</param>
    /// <returns>True on success; false on authentication failure, with the plaintext buffer cleared. With a zero tag size, returns true without verification.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="tagSize"/> is not 0, <see cref="MinTagSize"/>, or <see cref="MaxTagSize"/>,
    /// or when the lengths of <paramref name="ciphertext"/>, <paramref name="plaintext"/>, <paramref name="nonce16"/>, or <paramref name="key16"/> are invalid.
    /// </exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="plaintext"/> overlaps <paramref name="ciphertext"/> and starts after it.</exception>
    public static bool TryDecrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce16, ReadOnlySpan<byte> key16, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
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

        if (nonce16.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce16), nonce16.Length, $"{nameof(nonce16)} must be {NonceSize} bytes long.");
        }

        if (key16.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key16), key16.Length, $"{nameof(key16)} must be {KeySize} bytes long.");
        }

        if (ciphertext.Overlaps(plaintext, out var offset) && offset > 0)
        {// Each block would overwrite ciphertext that has not been read yet.
            throw new ArgumentException($"{nameof(plaintext)} must not start after an overlapping {nameof(ciphertext)}.", nameof(plaintext));
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
