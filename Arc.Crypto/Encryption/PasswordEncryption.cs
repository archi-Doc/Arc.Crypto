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
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password to use for encryption.</param>
    /// <returns>The encrypted data.<br/>
    ///  The size will be the data size plus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</returns>
    public static byte[] Encrypt(ReadOnlySpan<byte> data, string password)
        => Encrypt(data, Encoding.UTF8.GetBytes(password));

    /// <summary>
    /// Encrypts the specified data using the provided utf8 password.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The utf8 password to use for encryption.</param>
    /// <returns>The encrypted data.<br/>
    ///  The size will be the data size plus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</returns>
    public static byte[] Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> password)
    {// Encrypted: Salt[32] + EncryptedData + Tag[16]
        var buffer = new byte[SaltSize + data.Length + TagSize];

        var salt = buffer.AsSpan(0, SaltSize);
        CryptoRandom.NextBytes(salt);

        Span<byte> key = stackalloc byte[Aegis256.KeySize];
        CryptoPasswordHash.DeriveKey(password, salt.Slice(0, CryptoPasswordHash.SaltSize), key);

        var span = buffer.AsSpan();
        Aegis256.Encrypt(span.Slice(SaltSize, data.Length + TagSize), data, salt, key);

        return buffer;
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
    /// <param name="password">The utf8 password to use for decryption.</param>
    /// <param name="data">The decrypted data.<br/>
    /// The size will be the encrypted data size minus <see cref="SaltSize"/> and <see cref="TagSize"/>(48 in the current implementation).</param>
    /// <returns><c>true</c> if decryption was successful; otherwise, <c>false</c>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> password, out Memory<byte> data)
    {
        data = default;
        if (encrypted.Length < SaltSize + TagSize)
        {
            return false;
        }

        Span<byte> key = stackalloc byte[Aegis256.KeySize];
        CryptoPasswordHash.DeriveKey(password, encrypted.Slice(0, CryptoPasswordHash.SaltSize), key);

        var plaintext = new byte[encrypted.Length - SaltSize - TagSize];
        if (Aegis256.Decrypt(plaintext, encrypted.Slice(SaltSize), encrypted.Slice(0, Aegis256.NonceSize), key))
        {
            data = plaintext;
            return true;
        }
        else
        {
            return false;
        }
    }
}
