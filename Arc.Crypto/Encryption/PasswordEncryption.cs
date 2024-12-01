// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Arc.Crypto;

/// <summary>
/// Provides methods for encrypting and decrypting data using a password.<br/>
/// The size will be the data size plus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).<br/>
/// The algorithm uses Argon2id for key derivation and AEGIS-256 for encryption, providing a highly secure design.
/// </summary>
public static class PasswordEncryption
{
    public const int SaltSize = 32;
    public const int TagSize = 16;

    /// <summary>
    /// Encrypts the specified data using the provided password.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="password">The password to use for encryption.</param>
    /// <param name="ciphertext">The encrypted data.<br/>
    ///  The size will be the plaintext size plus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, string password, out byte[] ciphertext)
    {
        ciphertext = new byte[SaltSize + plaintext.Length + TagSize];
        Encrypt(plaintext, Encoding.UTF8.GetBytes(password), ciphertext);
    }

    /// <summary>
    /// Encrypts the specified data using the provided utf8 password.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="password">The password to use for encryption.</param>
    /// <param name="ciphertext">The encrypted data.<br/>
    ///  The size will be the data size plus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> password, out byte[] ciphertext)
    {
        ciphertext = new byte[SaltSize + plaintext.Length + TagSize];
        Encrypt(plaintext, password, ciphertext);
    }

    /// <summary>
    /// Encrypts the specified data using the provided password.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="password">The password to use for encryption.</param>
    /// <param name="ciphertext">The encrypted data.<br/>
    ///  The size will be the plaintext size plus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, string password, Span<byte> ciphertext)
        => Encrypt(plaintext, Encoding.UTF8.GetBytes(password), ciphertext);

    /// <summary>
    /// Encrypts the specified data using the provided utf8 password.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="utf8Password">The utf8 password to use for encryption.</param>
    /// <param name="ciphertext">The encrypted data.<br/>
    ///  The size will be the data size plus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> utf8Password, Span<byte> ciphertext)
    {// Encrypted: Salt[32] + EncryptedData + Tag[16]
        var cipherLength = SaltSize + plaintext.Length + TagSize;
        if (ciphertext.Length != cipherLength)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(ciphertext), cipherLength);
        }

        var salt = ciphertext.Slice(0, SaltSize);
        CryptoRandom.NextBytes(salt);

        Span<byte> key32 = stackalloc byte[Aegis256.KeySize];
        DeriveKey(utf8Password, salt, key32);

        Aegis256.Encrypt(ciphertext.Slice(SaltSize, plaintext.Length + TagSize), plaintext, salt, key32);
    }

    /// <summary>
    /// Tries to decrypt the specified encrypted data using the provided password.
    /// </summary>
    /// <param name="ciphertext">The encrypted data.<br/>
    /// The size must be at least <see cref="SaltSize"/>+<see cref="TagSize"/> (48 in the current implementation).</param>
    /// <param name="password">The password to use for decryption.</param>
    /// <param name="plaintext">The decrypted data.<br/>
    /// The size will be the encrypted data size minus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    /// <returns><c>true</c> if decryption was successful; otherwise, <c>false</c>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> ciphertext, string password, [MaybeNullWhen(false)] out byte[] plaintext)
    {
        if (ciphertext.Length < SaltSize + TagSize)
        {// Invalid size.
            plaintext = default;
            return false;
        }

        plaintext = new byte[ciphertext.Length - SaltSize - TagSize];
        if (TryDecrypt(ciphertext, Encoding.UTF8.GetBytes(password), plaintext))
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
    /// Tries to decrypt the specified encrypted data using the provided utf8 password.
    /// </summary>
    /// <param name="ciphertext">The encrypted data.<br/>
    /// The size must be at least <see cref="SaltSize"/>+<see cref="TagSize"/> (48 in the current implementation).</param>
    /// <param name="utf8Password">The utf 8password to use for decryption.</param>
    /// <param name="plaintext">The decrypted data.<br/>
    /// The size will be the encrypted data size minus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    /// <returns><c>true</c> if decryption was successful; otherwise, <c>false</c>.</returns>
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
    /// Tries to decrypt the specified encrypted data using the provided password.
    /// </summary>
    /// <param name="ciphertext">The encrypted data.<br/>
    /// The size must be at least <see cref="SaltSize"/>+<see cref="TagSize"/> (48 in the current implementation).</param>
    /// <param name="password">The password to use for decryption.</param>
    /// <param name="plaintext">The decrypted data.<br/>
    /// The size will be the encrypted data size minus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    /// <returns><c>true</c> if decryption was successful; otherwise, <c>false</c>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> ciphertext, string password, Span<byte> plaintext)
        => TryDecrypt(ciphertext, Encoding.UTF8.GetBytes(password), plaintext);

    /// <summary>
    /// Tries to decrypt the specified encrypted data using the provided utf8 password.
    /// </summary>
    /// <param name="ciphertext">The encrypted data.<br/>
    /// The size must be at least <see cref="SaltSize"/>+<see cref="TagSize"/> (48 in the current implementation).</param>
    /// <param name="utf8Password">The utf8 password to use for decryption.</param>
    /// <param name="plaintext">The decrypted data.<br/>
    /// The size will be the encrypted data size minus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    /// <returns><c>true</c> if decryption was successful; otherwise, <c>false</c>.</returns>
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
        DeriveKey(utf8Password, ciphertext, key32);

        if (Aegis256.TryDecrypt(plaintext, ciphertext.Slice(SaltSize), ciphertext.Slice(0, Aegis256.NonceSize), key32))
        {
            return true;
        }
        else
        {
            return false;
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
