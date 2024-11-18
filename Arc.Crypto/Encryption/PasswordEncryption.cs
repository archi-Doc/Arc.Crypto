// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

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
    /// <param name="password">The password to use for encryption.</param>
    /// <param name="ciphertext">The encrypted data.<br/>
    ///  The size will be the data size plus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> password, out byte[] ciphertext)
    {
        ciphertext = new byte[SaltSize + plaintext.Length + TagSize];
        Encrypt(plaintext, password, ciphertext);
    }

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
            CryptoHelper.ThrowSizeMismatchException(nameof(ciphertext), cipherLength);
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
    /// <param name="encrypted">The encrypted data.<br/>
    /// The size must be at least <see cref="SaltSize"/>+<see cref="TagSize"/> (48 in the current implementation).</param>
    /// <param name="password">The password to use for decryption.</param>
    /// <param name="data">The decrypted data.<br/>
    /// The size will be the encrypted data size minus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    /// <returns><c>true</c> if decryption was successful; otherwise, <c>false</c>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> encrypted, string password, out Memory<byte> data) => TryDecrypt(encrypted, Encoding.UTF8.GetBytes(password), out data);

    /// <summary>
    /// Tries to decrypt the specified encrypted data using the provided utf8 password.
    /// </summary>
    /// <param name="encrypted">The encrypted data.<br/>
    /// The size must be at least <see cref="SaltSize"/>+<see cref="TagSize"/> (48 in the current implementation).</param>
    /// <param name="utf8Password">The utf8 password to use for decryption.</param>
    /// <param name="data">The decrypted data.<br/>
    /// The size will be the encrypted data size minus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    /// <returns><c>true</c> if decryption was successful; otherwise, <c>false</c>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> utf8Password, out Memory<byte> data)
    {
        data = default;
        if (encrypted.Length < SaltSize + TagSize)
        {
            return false;
        }

        Span<byte> key32 = stackalloc byte[Aegis256.KeySize];
        DeriveKey(utf8Password, encrypted, key32);

        var plaintext = new byte[encrypted.Length - SaltSize - TagSize];
        if (Aegis256.TryDecrypt(plaintext, encrypted.Slice(SaltSize), encrypted.Slice(0, Aegis256.NonceSize), key32))
        {
            data = plaintext;
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
