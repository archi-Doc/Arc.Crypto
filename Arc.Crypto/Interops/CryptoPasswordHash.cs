// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;
using System.Text;

namespace Arc.Crypto;

/// <summary>
/// Functions to compute a hash from a password.<br/>
/// It is primarily used for key derivation and password storage.<br/>
/// Libsodium/Argon2 is used, and due to its nature, it is designed to consume CPU and memory resources.
/// </summary>
public static class CryptoPasswordHash
{
    /// <summary>
    /// The minimum size of a derived key in bytes.
    /// </summary>
    public const int MinimumKeySize = 16; // crypto_pwhash_BYTES_MIN crypto_pwhash_argon2id_BYTES_MIN

    /// <summary>
    /// The size of the salt in bytes.
    /// </summary>
    public const int SaltSize = 16; // crypto_pwhash_SALTBYTES crypto_pwhash_argon2id_SALTBYTES

    /// <summary>
    /// The buffer size in bytes required for a hash string, including the terminating null character.
    /// </summary>
    public const int HashStringLength = 128; // crypto_pwhash_STRBYTES crypto_pwhash_argon2id_STRBYTES

    private const int DefaultAlgorithm = 2; // crypto_pwhash_ALG_DEFAULT crypto_pwhash_ALG_ARGON2ID13 crypto_pwhash_argon2id_ALG_ARGON2ID13

    /// <summary>
    /// The computational cost of the Argon2id hash. A higher value increases the number of passes over memory.
    /// </summary>
    public enum OpsLimit
    {
        /// <summary>
        /// Suitable for interactive use, such as login.
        /// </summary>
        Interactive = 2, // crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE 2U

        /// <summary>
        /// A balance between <see cref="Interactive"/> and <see cref="Sensitive"/>.
        /// </summary>
        Moderate = 3, // crypto_pwhash_argon2id_OPSLIMIT_MODERATE 3U

        /// <summary>
        /// Suitable for highly sensitive data, at the cost of a noticeably longer computation.
        /// </summary>
        Sensitive = 4, // crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE 4U
    }

    /// <summary>
    /// The amount of memory the Argon2id hash is allowed to use, in bytes.
    /// </summary>
    public enum MemLimit
    {
        /// <summary>
        /// 64 MiB, suitable for interactive use.
        /// </summary>
        Interactive = 67108864, // 64 MiB

        /// <summary>
        /// 256 MiB, a balance between <see cref="Interactive"/> and <see cref="Sensitive"/>.
        /// </summary>
        Moderate = 268435456, // 256 MiB

        /// <summary>
        /// 1024 MiB, suitable for highly sensitive data.
        /// </summary>
        Sensitive = 1073741824, // 1024 MiB
    }

    /// <summary>
    /// Derives a key from a password and salt using the specified computational and memory limits.
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="salt16">The salt to use for key derivation. Must be <see cref="SaltSize"/>(16) bytes long.</param>
    /// <param name="key">The buffer to store the derived key. Must be at least <see cref="MinimumKeySize"/>(16) bytes long.</param>
    /// <param name="opsLimit">The computational cost parameter.</param>
    /// <param name="memLimit">The memory cost parameter.</param>
    /// <exception cref="ArgumentOutOfRangeException">The salt size is invalid or the output is too short.</exception>
    /// <exception cref="CryptographicException">Key derivation failed; the key buffer is cleared.</exception>
    public static void DeriveKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt16, Span<byte> key, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        using var utf8 = new Utf8Password(password, buffer);
        DeriveKey(utf8.Bytes, salt16, key, opsLimit, memLimit);
    }

    /// <summary>
    /// Derives a key from a utf8 password and salt using the specified computational and memory limits.
    /// </summary>
    /// <param name="utf8Password">The utf8 password to derive the key from.</param>
    /// <param name="salt16">The salt to use for key derivation. Must be <see cref="SaltSize"/>(16) bytes long.</param>
    /// <param name="key">The buffer to store the derived key. Must be at least <see cref="MinimumKeySize"/>(16) bytes long.</param>
    /// <param name="opsLimit">The computational cost parameter.</param>
    /// <param name="memLimit">The memory cost parameter.</param>
    /// <exception cref="ArgumentOutOfRangeException">The salt size is invalid or the output is too short.</exception>
    /// <exception cref="CryptographicException">Thrown when key derivation fails, typically because the requested memory could not be allocated.</exception>
    public static void DeriveKey(ReadOnlySpan<byte> utf8Password, ReadOnlySpan<byte> salt16, Span<byte> key, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        if (salt16.Length != SaltSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(salt16), SaltSize);
        }

        if (key.Length < MinimumKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"The {nameof(key)} length must be at least {MinimumKeySize} bytes.");
        }

        if (LibsodiumInterops.crypto_pwhash(key, (ulong)key.Length, utf8Password, (ulong)utf8Password.Length, salt16, (ulong)opsLimit, (UIntPtr)memLimit, DefaultAlgorithm) != 0)
        {// Do not leave a partially written key behind; a caller that ignores the failure must not receive a usable key.
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException("Key derivation failed. The requested memory limit may not be available.");
        }
    }

    /// <summary>
    /// Computes a hash string from a password using the specified computational and memory limits.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <param name="opsLimit">The computational cost parameter.</param>
    /// <param name="memLimit">The memory cost parameter.</param>
    /// <returns>The computed hash string.<br/>
    /// The maximum length is <see cref="HashStringLength"/>(128).</returns>
    /// <exception cref="CryptographicException">Thrown when password hashing fails.</exception>
    public static string GetHashString(string password, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        ArgumentNullException.ThrowIfNull(password);
        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        using var utf8Password = new Utf8Password(password, buffer);
        Span<byte> utf8 = stackalloc byte[HashStringLength];
        var hashLength = GenerateHashString(utf8Password.Bytes, utf8, opsLimit, memLimit);
        return Encoding.UTF8.GetString(utf8[..hashLength]);
    }

    /// <summary>
    /// Computes a hash string from a utf8 password using the specified computational and memory limits.
    /// </summary>
    /// <param name="utf8Password">The utf8 password to hash.</param>
    /// <param name="opsLimit">The computational cost parameter.</param>
    /// <param name="memLimit">The memory cost parameter.</param>
    /// <returns>The computed hash string.<br/>
    /// The maximum length is <see cref="HashStringLength"/>(128).</returns>
    /// <exception cref="CryptographicException">Thrown when password hashing fails.</exception>
    public static byte[] GetHashString(ReadOnlySpan<byte> utf8Password, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        Span<byte> utf8 = stackalloc byte[HashStringLength];
        var length = GenerateHashString(utf8Password, utf8, opsLimit, memLimit);
        return utf8[..length].ToArray();
    }

    /// <summary>
    /// Verifies a password using the salt and cost parameters encoded in the hash string.
    /// </summary>
    /// <param name="hashString">The hash string to verify against.<br/>
    ///  The length must be less than or equal to <see cref="HashStringLength"/>(128).</param>
    /// <param name="password">The password to verify.</param>
    /// <param name="opsLimit">Unused; the computational cost is encoded in the hash string.</param>
    /// <param name="memLimit">Unused; the memory cost is encoded in the hash string.</param>
    /// <returns>True if the password matches the hash string; otherwise, false.</returns>
    public static bool VerifyHashString(string hashString, string password, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        var length = Encoding.UTF8.GetByteCount(hashString);
        if (length > HashStringLength)
        {
            return false;
        }

        Span<byte> utf8hashString = stackalloc byte[length];
        Encoding.UTF8.GetBytes(hashString, utf8hashString);
        ArgumentNullException.ThrowIfNull(password);
        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        using var utf8Password = new Utf8Password(password, buffer);
        return VerifyHashString(utf8hashString, utf8Password.Bytes, opsLimit, memLimit);
    }

    /// <summary>
    /// Verifies a UTF-8 password using the salt and cost parameters encoded in the hash string.
    /// </summary>
    /// <param name="utf8HashString">The utf8 hash string to verify against.<br/>
    ///  The length must be less than or equal to <see cref="HashStringLength"/>(128).</param>
    /// <param name="utf8Password">The utf8 password to verify.</param>
    /// <param name="opsLimit">Unused; the computational cost is encoded in the hash string.</param>
    /// <param name="memLimit">Unused; the memory cost is encoded in the hash string.</param>
    /// <returns>True if the password matches the hash string; otherwise, false.</returns>
    public static bool VerifyHashString(ReadOnlySpan<byte> utf8HashString, ReadOnlySpan<byte> utf8Password, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        if (utf8HashString.Length > HashStringLength)
        {
            return false;
        }

        if (utf8HashString.Length == HashStringLength)
        {
            // The native API expects a C string, including its null terminator.
            return utf8HashString.Contains((byte)0)
                && LibsodiumInterops.crypto_pwhash_str_verify(utf8HashString, utf8Password, (ulong)utf8Password.Length) == 0;
        }

        Span<byte> buffer = stackalloc byte[HashStringLength];
        buffer.Clear();
        utf8HashString.CopyTo(buffer);
        return LibsodiumInterops.crypto_pwhash_str_verify(buffer, utf8Password, (ulong)utf8Password.Length) == 0;
    }

    private static int GenerateHashString(ReadOnlySpan<byte> utf8Password, Span<byte> destination, OpsLimit opsLimit, MemLimit memLimit)
    {
        if (LibsodiumInterops.crypto_pwhash_str(destination, utf8Password, (ulong)utf8Password.Length, (ulong)opsLimit, (UIntPtr)memLimit) != 0)
        {
            throw new CryptographicException("Password hashing failed. The requested cost parameters may be invalid or unavailable.");
        }

        return destination.IndexOf((byte)0);
    }
}
