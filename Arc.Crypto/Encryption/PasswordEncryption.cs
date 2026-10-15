// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// Encrypts and decrypts data with a password, using Argon2id (2 passes, 64 MiB) for key derivation and AEGIS-256 for encryption.<br/>
/// Format: Salt(32) + encrypted data + Tag(16), so the output is <see cref="SaltSize"/> + <see cref="TagSize"/> (48) bytes longer than the data.<br/>
/// The salt is the AEGIS-256 nonce, and its first 16 bytes are the Argon2id salt.<br/>
/// An empty password skips Argon2id and uses the public salt as the key, so it provides no secrecy.
/// </summary>
/// <remarks>
/// Without hardware AES, AEGIS-256 falls back to a table-based software AES that is not constant-time (see <see cref="Aegis256"/>).
/// </remarks>
public static class PasswordEncryption
{
    /// <summary>
    /// The size of the salt in bytes, which is also used as the AEGIS-256 nonce.
    /// </summary>
    public const int SaltSize = 32;

    /// <summary>
    /// The size of the authentication tag in bytes.
    /// </summary>
    public const int TagSize = 16;

    /// <summary>
    /// Encrypts data with a password into a new array.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="password">The password (encoded as UTF-8; unpaired surrogates become U+FFFD). An empty password provides no secrecy.</param>
    /// <param name="ciphertext">Receives Salt(32) + encrypted data + Tag(16), the plaintext length + 48 bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">Argon2id key derivation failed, typically because the required memory could not be allocated.</exception>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, string password, out byte[] ciphertext)
    {
        ciphertext = new byte[checked(SaltSize + plaintext.Length + TagSize)];
        Encrypt(plaintext, password, ciphertext);
    }

    /// <summary>
    /// Encrypts data with a UTF-8 password into a new array.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="utf8Password">The UTF-8 password. An empty password provides no secrecy.</param>
    /// <param name="ciphertext">Receives Salt(32) + encrypted data + Tag(16), the plaintext length + 48 bytes.</param>
    /// <exception cref="CryptographicException">Argon2id key derivation failed, typically because the required memory could not be allocated.</exception>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> utf8Password, out byte[] ciphertext)
    {
        ciphertext = new byte[checked(SaltSize + plaintext.Length + TagSize)];
        Encrypt(plaintext, utf8Password, ciphertext);
    }

    /// <summary>
    /// Encrypts data with a password into a caller-provided buffer.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="password">The password (encoded as UTF-8; unpaired surrogates become U+FFFD). An empty password provides no secrecy.</param>
    /// <param name="ciphertext">The output buffer: Salt(32) + encrypted data + Tag(16).<br/>
    /// The size must be exactly the plaintext length + <see cref="SaltSize"/> + <see cref="TagSize"/> (48 bytes).<br/>
    /// For in-place operation, place <paramref name="plaintext"/> at offset <see cref="SaltSize"/> of this buffer.</param>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The size of <paramref name="ciphertext"/> is invalid.</exception>
    /// <exception cref="ArgumentException"><paramref name="plaintext"/> overlaps <paramref name="ciphertext"/> and starts before offset <see cref="SaltSize"/> of it.</exception>
    /// <exception cref="CryptographicException">Argon2id key derivation failed, typically because the required memory could not be allocated.</exception>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, string password, Span<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(password);
        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        using var utf8 = new Utf8Password(password, buffer);
        Encrypt(plaintext, utf8.Bytes, ciphertext);
    }

    /// <summary>
    /// Encrypts data with a UTF-8 password into a caller-provided buffer.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="utf8Password">The UTF-8 password. An empty password provides no secrecy. It may overlap <paramref name="ciphertext"/>.</param>
    /// <param name="ciphertext">The output buffer: Salt(32) + encrypted data + Tag(16).<br/>
    /// The size must be exactly the plaintext length + <see cref="SaltSize"/> + <see cref="TagSize"/> (48 bytes).<br/>
    /// For in-place operation, place <paramref name="plaintext"/> at offset <see cref="SaltSize"/> of this buffer.</param>
    /// <exception cref="ArgumentOutOfRangeException">The size of <paramref name="ciphertext"/> is invalid.</exception>
    /// <exception cref="ArgumentException"><paramref name="plaintext"/> overlaps <paramref name="ciphertext"/> and starts before offset <see cref="SaltSize"/> of it.</exception>
    /// <exception cref="CryptographicException">Argon2id key derivation failed, typically because the required memory could not be allocated.</exception>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> utf8Password, Span<byte> ciphertext)
    {// Encrypted: Salt[32] + EncryptedData + Tag[16]
        var cipherLength = checked(SaltSize + plaintext.Length + TagSize);
        if (ciphertext.Length != cipherLength)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(ciphertext), cipherLength);
        }

        if (plaintext.Overlaps(ciphertext, out var offset) && offset > -SaltSize)
        {// The salt or an encrypted block would overwrite plaintext that has not been read yet.
            throw new ArgumentException($"{nameof(plaintext)} must not overlap {nameof(ciphertext)} before offset {SaltSize}.", nameof(plaintext));
        }

        // The salt would overwrite a password stored in the salt region before it is read, so generate it in a separate buffer in that case.
        var saltInPlace = !utf8Password.Overlaps(ciphertext.Slice(0, SaltSize));
        Span<byte> salt = saltInPlace ? ciphertext.Slice(0, SaltSize) : stackalloc byte[SaltSize];
        CryptoRandom.NextBytes(salt);

        Span<byte> key32 = stackalloc byte[Aegis256.KeySize];
        try
        {
            DeriveKey(utf8Password, salt, key32);
            if (!saltInPlace)
            {
                salt.CopyTo(ciphertext);
            }

            Aegis256.Encrypt(ciphertext.Slice(SaltSize, plaintext.Length + TagSize), plaintext, salt, key32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key32);
        }
    }

    /// <summary>
    /// Tries to decrypt data encrypted with a password.
    /// </summary>
    /// <param name="ciphertext">Salt(32) + encrypted data + Tag(16). Input shorter than <see cref="SaltSize"/> + <see cref="TagSize"/> (48 bytes) returns <see langword="false"/>.</param>
    /// <param name="password">The password used for encryption (encoded as UTF-8; unpaired surrogates become U+FFFD).</param>
    /// <param name="plaintext">The decrypted data (the ciphertext length minus 48 bytes), or <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> if the password is correct and the data is authentic; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">Argon2id key derivation failed, typically because the required memory could not be allocated.</exception>
    public static bool TryDecrypt(ReadOnlySpan<byte> ciphertext, string password, [MaybeNullWhen(false)] out byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (ciphertext.Length < SaltSize + TagSize)
        {// Invalid size.
            plaintext = default;
            return false;
        }

        plaintext = new byte[ciphertext.Length - SaltSize - TagSize];
        if (TryDecrypt(ciphertext, password, plaintext))
        {
            return true;
        }
        else
        {
            plaintext = default;
            return false;
        }
    }

    /// <summary>
    /// Tries to decrypt data encrypted with a UTF-8 password.
    /// </summary>
    /// <param name="ciphertext">Salt(32) + encrypted data + Tag(16). Input shorter than <see cref="SaltSize"/> + <see cref="TagSize"/> (48 bytes) returns <see langword="false"/>.</param>
    /// <param name="utf8Password">The UTF-8 password used for encryption.</param>
    /// <param name="plaintext">The decrypted data (the ciphertext length minus 48 bytes), or <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> if the password is correct and the data is authentic; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="CryptographicException">Argon2id key derivation failed, typically because the required memory could not be allocated.</exception>
    public static bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> utf8Password, [MaybeNullWhen(false)] out byte[] plaintext)
    {
        if (ciphertext.Length < SaltSize + TagSize)
        {// Invalid size.
            plaintext = default;
            return false;
        }

        plaintext = new byte[ciphertext.Length - SaltSize - TagSize];
        if (TryDecrypt(ciphertext, utf8Password, plaintext))
        {
            return true;
        }
        else
        {
            plaintext = default;
            return false;
        }
    }

    /// <summary>
    /// Tries to decrypt data encrypted with a password into a caller-provided buffer.
    /// </summary>
    /// <param name="ciphertext">Salt(32) + encrypted data + Tag(16). Input shorter than <see cref="SaltSize"/> + <see cref="TagSize"/> (48 bytes) returns <see langword="false"/>.</param>
    /// <param name="password">The password used for encryption (encoded as UTF-8; unpaired surrogates become U+FFFD).</param>
    /// <param name="plaintext">The output buffer. The size must be exactly the ciphertext length minus 48 bytes. It is cleared if authentication fails.<br/>
    /// It may overlap <paramref name="ciphertext"/> if it starts at or before offset <see cref="SaltSize"/> of it (in-place decryption).</param>
    /// <returns><see langword="true"/> if the password is correct and the data is authentic; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The size of <paramref name="plaintext"/> is invalid.</exception>
    /// <exception cref="ArgumentException"><paramref name="plaintext"/> overlaps <paramref name="ciphertext"/> and starts after offset <see cref="SaltSize"/> of it.</exception>
    /// <exception cref="CryptographicException">Argon2id key derivation failed, typically because the required memory could not be allocated.</exception>
    public static bool TryDecrypt(ReadOnlySpan<byte> ciphertext, string password, Span<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (ciphertext.Length < SaltSize + TagSize)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        using var utf8 = new Utf8Password(password, buffer);
        return TryDecrypt(ciphertext, utf8.Bytes, plaintext);
    }

    /// <summary>
    /// Tries to decrypt data encrypted with a UTF-8 password into a caller-provided buffer.
    /// </summary>
    /// <param name="ciphertext">Salt(32) + encrypted data + Tag(16). Input shorter than <see cref="SaltSize"/> + <see cref="TagSize"/> (48 bytes) returns <see langword="false"/>.</param>
    /// <param name="utf8Password">The UTF-8 password used for encryption.</param>
    /// <param name="plaintext">The output buffer. The size must be exactly the ciphertext length minus 48 bytes. It is cleared if authentication fails.<br/>
    /// It may overlap <paramref name="ciphertext"/> if it starts at or before offset <see cref="SaltSize"/> of it (in-place decryption).</param>
    /// <returns><see langword="true"/> if the password is correct and the data is authentic; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The size of <paramref name="plaintext"/> is invalid.</exception>
    /// <exception cref="ArgumentException"><paramref name="plaintext"/> overlaps <paramref name="ciphertext"/> and starts after offset <see cref="SaltSize"/> of it.</exception>
    /// <exception cref="CryptographicException">Argon2id key derivation failed, typically because the required memory could not be allocated.</exception>
    public static bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> utf8Password, Span<byte> plaintext)
    {
        if (ciphertext.Length < SaltSize + TagSize)
        {
            return false;
        }

        var plainLength = ciphertext.Length - SaltSize - TagSize;
        if (plaintext.Length != plainLength)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(plaintext), plainLength);
        }

        Span<byte> key32 = stackalloc byte[Aegis256.KeySize];
        try
        {
            DeriveKey(utf8Password, ciphertext, key32);
            return Aegis256.TryDecrypt(plaintext, ciphertext.Slice(SaltSize), ciphertext.Slice(0, Aegis256.NonceSize), key32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key32);
        }
    }

    private static void DeriveKey(ReadOnlySpan<byte> utf8Password, ReadOnlySpan<byte> salt, Span<byte> key32)
    {
        if (utf8Password.Length == 0)
        {// Skip Argon2id if the password is empty.
            salt.Slice(0, Aegis256.KeySize).CopyTo(key32);
        }
        else
        {
            CryptoPasswordHash.DeriveKey(utf8Password, salt.Slice(0, CryptoPasswordHash.SaltSize), key32);
        }
    }
}
