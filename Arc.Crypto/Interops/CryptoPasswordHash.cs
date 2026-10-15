// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
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
    public const int MaxHashStringLength = 128; // crypto_pwhash_STRBYTES crypto_pwhash_argon2id_STRBYTES

    private const int DefaultAlgorithm = 2; // crypto_pwhash_ALG_DEFAULT crypto_pwhash_ALG_ARGON2ID13 crypto_pwhash_argon2id_ALG_ARGON2ID13
    private const int MaxStackKeySize = 64;

    /// <summary>
    /// The computational cost of the Argon2id hash. A higher value increases the number of passes over memory.
    /// </summary>
    public enum OperationLimit
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
    public enum MemoryLimit
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
    /// <param name="password">The password to derive the key from (encoded as UTF-8; unpaired surrogates become U+FFFD).</param>
    /// <param name="salt16">The salt to use for key derivation. Must be <see cref="SaltSize"/>(16) bytes long.</param>
    /// <param name="key">The buffer to store the derived key. Must be at least <see cref="MinimumKeySize"/>(16) bytes long.<br/>
    /// It may overlap <paramref name="salt16"/>.</param>
    /// <param name="operationLimit">The computational cost parameter.</param>
    /// <param name="memoryLimit">The memory cost parameter.</param>
    /// <exception cref="ArgumentOutOfRangeException">The salt size is invalid or the output is too short.</exception>
    /// <exception cref="CryptographicException">Key derivation failed, typically because the requested memory could not be allocated; the key buffer is cleared.</exception>
    public static void DeriveKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt16, Span<byte> key, OperationLimit operationLimit = OperationLimit.Interactive, MemoryLimit memoryLimit = MemoryLimit.Interactive)
    {
        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        using var utf8 = new Utf8Password(password, buffer);
        DeriveKey(utf8.Bytes, salt16, key, operationLimit, memoryLimit);
    }

    /// <summary>
    /// Derives a key from a UTF-8 password and salt using the specified computational and memory limits.
    /// </summary>
    /// <param name="utf8Password">The UTF-8 password to derive the key from.</param>
    /// <param name="salt16">The salt to use for key derivation. Must be <see cref="SaltSize"/>(16) bytes long.</param>
    /// <param name="key">The buffer to store the derived key. Must be at least <see cref="MinimumKeySize"/>(16) bytes long.<br/>
    /// It may overlap <paramref name="utf8Password"/> or <paramref name="salt16"/>.</param>
    /// <param name="operationLimit">The computational cost parameter.</param>
    /// <param name="memoryLimit">The memory cost parameter.</param>
    /// <exception cref="ArgumentOutOfRangeException">The salt size is invalid or the output is too short.</exception>
    /// <exception cref="CryptographicException">Key derivation failed, typically because the requested memory could not be allocated; the key buffer is cleared.</exception>
    public static void DeriveKey(ReadOnlySpan<byte> utf8Password, ReadOnlySpan<byte> salt16, Span<byte> key, OperationLimit operationLimit = OperationLimit.Interactive, MemoryLimit memoryLimit = MemoryLimit.Interactive)
    {
        if (salt16.Length != SaltSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(salt16), SaltSize);
        }

        if (key.Length < MinimumKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"The {nameof(key)} length must be at least {MinimumKeySize} bytes.");
        }

        if (!key.Overlaps(salt16) && !key.Overlaps(utf8Password))
        {
            if (LibsodiumInterops.crypto_pwhash(key, (ulong)key.Length, utf8Password, (ulong)utf8Password.Length, salt16, (ulong)operationLimit, (UIntPtr)memoryLimit, DefaultAlgorithm) != 0)
            {
                ThrowDeriveKeyFailed(key);
            }

            return;
        }

        // Libsodium writes the output before it reads the password and salt, so derive into a separate buffer.
        byte[]? rented = null;
        Span<byte> temp = key.Length <= MaxStackKeySize ? stackalloc byte[MaxStackKeySize] : (rented = ArrayPool<byte>.Shared.Rent(key.Length));
        temp = temp.Slice(0, key.Length);
        try
        {
            if (LibsodiumInterops.crypto_pwhash(temp, (ulong)temp.Length, utf8Password, (ulong)utf8Password.Length, salt16, (ulong)operationLimit, (UIntPtr)memoryLimit, DefaultAlgorithm) != 0)
            {
                ThrowDeriveKeyFailed(key);
            }

            temp.CopyTo(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(temp);
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Computes an Argon2id hash string ("$argon2id$v=19$m=...,t=...,p=1$salt$hash") that encodes a random salt and the cost parameters.
    /// </summary>
    /// <param name="password">The password to hash (encoded as UTF-8; unpaired surrogates become U+FFFD).</param>
    /// <param name="operationLimit">The computational cost parameter.</param>
    /// <param name="memoryLimit">The memory cost parameter.</param>
    /// <returns>The ASCII hash string, at most <see cref="MaxHashStringLength"/> - 1 (127) characters.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">Password hashing failed, typically because the requested memory could not be allocated.</exception>
    public static string GetHashString(string password, OperationLimit operationLimit = OperationLimit.Interactive, MemoryLimit memoryLimit = MemoryLimit.Interactive)
    {
        ArgumentNullException.ThrowIfNull(password);
        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        using var utf8Password = new Utf8Password(password, buffer);
        Span<byte> utf8 = stackalloc byte[MaxHashStringLength];
        var hashLength = GenerateHashString(utf8Password.Bytes, utf8, operationLimit, memoryLimit);
        return Encoding.UTF8.GetString(utf8[..hashLength]);
    }

    /// <summary>
    /// Computes an Argon2id hash string from a UTF-8 password; see <see cref="GetHashString"/>.
    /// </summary>
    /// <param name="utf8Password">The UTF-8 password to hash.</param>
    /// <param name="operationLimit">The computational cost parameter.</param>
    /// <param name="memoryLimit">The memory cost parameter.</param>
    /// <returns>The hash string as ASCII bytes without a null terminator, at most <see cref="MaxHashStringLength"/> - 1 (127) bytes.</returns>
    /// <exception cref="CryptographicException">Password hashing failed, typically because the requested memory could not be allocated.</exception>
    public static byte[] GetUtf8HashString(ReadOnlySpan<byte> utf8Password, OperationLimit operationLimit = OperationLimit.Interactive, MemoryLimit memoryLimit = MemoryLimit.Interactive)
    {
        Span<byte> utf8 = stackalloc byte[MaxHashStringLength];
        var length = GenerateHashString(utf8Password, utf8, operationLimit, memoryLimit);
        return utf8[..length].ToArray();
    }

    /// <summary>
    /// Verifies a password using the salt and cost parameters encoded in the hash string.
    /// </summary>
    /// <param name="hashString">The hash string from <see cref="GetHashString"/>; anything after the first null character is ignored.
    /// Up to <see cref="MaxHashStringLength"/> (128) UTF-8 bytes including an optional null terminator; longer input returns <see langword="false"/>.</param>
    /// <param name="password">The password to verify (encoded as UTF-8; unpaired surrogates become U+FFFD).</param>
    /// <param name="operationLimit">Unused; the computational cost is encoded in the hash string.</param>
    /// <param name="memoryLimit">Unused; the memory cost is encoded in the hash string.</param>
    /// <returns><see langword="true"/> if the password matches; <see langword="false"/> if it does not, or if the hash string is malformed or too long.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="hashString"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    public static bool VerifyHashString(string hashString, string password, OperationLimit operationLimit = OperationLimit.Interactive, MemoryLimit memoryLimit = MemoryLimit.Interactive)
    {
        ArgumentNullException.ThrowIfNull(hashString);
        ArgumentNullException.ThrowIfNull(password);
        var length = Encoding.UTF8.GetByteCount(hashString);
        if (length > MaxHashStringLength)
        {
            return false;
        }

        Span<byte> utf8hashString = stackalloc byte[length];
        Encoding.UTF8.GetBytes(hashString, utf8hashString);
        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        using var utf8Password = new Utf8Password(password, buffer);
        return VerifyHashString(utf8hashString, utf8Password.Bytes, operationLimit, memoryLimit);
    }

    /// <summary>
    /// Verifies a UTF-8 password using the salt and cost parameters encoded in the hash string.
    /// </summary>
    /// <param name="utf8HashString">The hash string bytes, optionally null-terminated.<br/>
    /// Up to <see cref="MaxHashStringLength"/> (128) bytes including the terminator; longer input returns <see langword="false"/>.</param>
    /// <param name="utf8Password">The UTF-8 password to verify.</param>
    /// <param name="operationLimit">Unused; the computational cost is encoded in the hash string.</param>
    /// <param name="memoryLimit">Unused; the memory cost is encoded in the hash string.</param>
    /// <returns><see langword="true"/> if the password matches; <see langword="false"/> if it does not, or if the hash string is malformed or too long.</returns>
    public static bool VerifyHashString(ReadOnlySpan<byte> utf8HashString, ReadOnlySpan<byte> utf8Password, OperationLimit operationLimit = OperationLimit.Interactive, MemoryLimit memoryLimit = MemoryLimit.Interactive)
    {
        if (utf8HashString.Length > MaxHashStringLength)
        {
            return false;
        }

        if (utf8HashString.Length == MaxHashStringLength)
        {
            // The native API expects a C string, including its null terminator.
            return utf8HashString.Contains((byte)0)
                && LibsodiumInterops.crypto_pwhash_str_verify(utf8HashString, utf8Password, (ulong)utf8Password.Length) == 0;
        }

        Span<byte> buffer = stackalloc byte[MaxHashStringLength];
        buffer.Clear();
        utf8HashString.CopyTo(buffer);
        return LibsodiumInterops.crypto_pwhash_str_verify(buffer, utf8Password, (ulong)utf8Password.Length) == 0;
    }

    private static int GenerateHashString(ReadOnlySpan<byte> utf8Password, Span<byte> destination, OperationLimit operationLimit, MemoryLimit memoryLimit)
    {
        if (LibsodiumInterops.crypto_pwhash_str(destination, utf8Password, (ulong)utf8Password.Length, (ulong)operationLimit, (UIntPtr)memoryLimit) != 0)
        {
            throw new CryptographicException("Password hashing failed. The requested cost parameters may be invalid or unavailable.");
        }

        return destination.IndexOf((byte)0);
    }

    [DoesNotReturn]
    private static void ThrowDeriveKeyFailed(Span<byte> key)
    {// Do not leave a partially written key behind; a caller that ignores the failure must not receive a usable key.
        CryptographicOperations.ZeroMemory(key);
        throw new CryptographicException("Key derivation failed. The requested memory limit may not be available.");
    }
}
