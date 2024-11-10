// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Text;

namespace Arc.Crypto;

/// <summary>
/// Functions to compute a hash from a password.<br/>
/// It is primarily used for key derivation and password storage.<br/>
/// Libsodium/Argon2 is used, and due to its nature, it is designed to consume CPU and memory resources.
/// </summary>
public static class CryptoPasswordHash
{
    public const int MinimumKeySize = 16; // crypto_pwhash_BYTES_MIN crypto_pwhash_argon2id_BYTES_MIN
    public const int SaltSize = 16; // crypto_pwhash_SALTBYTES crypto_pwhash_argon2id_SALTBYTES
    public const int HashStringLength = 128; // crypto_pwhash_STRBYTES crypto_pwhash_argon2id_STRBYTES

    private const int DefaultAlgorithm = 2; // crypto_pwhash_ALG_DEFAULT crypto_pwhash_ALG_ARGON2ID13 crypto_pwhash_argon2id_ALG_ARGON2ID13

    public enum OpsLimit
    {
        Interactive = 2, // crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE 2U
        Moderate = 3, // crypto_pwhash_argon2id_OPSLIMIT_MODERATE 3U
        Sensitive = 4, // crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE 4U
    }

    public enum MemLimit
    {
        Interactive = 67108864, // 64 MiB
        Moderate = 268435456, // 256 MiB
        Sensitive = 1073741824, // 1024 MiB
    }

    public static void DeriveKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt16, Span<byte> key, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        var utf8Password = new byte[Encoding.UTF8.GetByteCount(password)];
        Encoding.UTF8.GetBytes(password, utf8Password);

        DeriveKey(utf8Password, salt16, key, opsLimit, memLimit);
    }

    public static void DeriveKey(ReadOnlySpan<byte> utf8Password, ReadOnlySpan<byte> salt16, Span<byte> key, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        if (salt16.Length != SaltSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(salt16), SaltSize);
        }

        if (key.Length < MinimumKeySize)
        {
            throw new ArgumentOutOfRangeException($"The {nameof(key)} length must be at least {MinimumKeySize} bytes.");
        }

        var success = LibsodiumInterops.crypto_pwhash(key, (ulong)key.Length, utf8Password, (ulong)utf8Password.Length, salt16, (ulong)opsLimit, (UIntPtr)memLimit, DefaultAlgorithm) >= 0;
    }

    public static string GetHashString(string password, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        var utf8Password = new byte[Encoding.UTF8.GetByteCount(password)];
        Encoding.UTF8.GetBytes(password, utf8Password);

        Span<byte> utf8 = stackalloc byte[HashStringLength];
        LibsodiumInterops.crypto_pwhash_str(utf8, utf8Password, (ulong)utf8Password.Length, (ulong)opsLimit, (UIntPtr)memLimit);

        var trimmed = CryptoHelper.TrimAtFirstNull(utf8);
        return Encoding.UTF8.GetString(trimmed);
    }

    public static byte[] GetHashString(ReadOnlySpan<byte> utf8Password, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {// Span<byte> utf8 = stackalloc byte[HashStringLength];
        var utf8 = new byte[HashStringLength];
        LibsodiumInterops.crypto_pwhash_str(utf8, utf8Password, (ulong)utf8Password.Length, (ulong)opsLimit, (UIntPtr)memLimit);

        utf8 = CryptoHelper.TrimAtFirstNull(utf8);
        return utf8;
    }

    public static bool VerifyHashString(string hashString, string password, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        var length = Encoding.UTF8.GetByteCount(hashString);
        if (length > HashStringLength)
        {
            return false;
        }

        var utf8hashString = new byte[HashStringLength]; // Fixed size
        Encoding.UTF8.GetBytes(hashString, utf8hashString);
        var utf8Password = new byte[Encoding.UTF8.GetByteCount(password)];
        Encoding.UTF8.GetBytes(password, utf8Password);

        return LibsodiumInterops.crypto_pwhash_str_verify(utf8hashString, utf8Password, (ulong)utf8Password.Length) == 0;
    }

    public static bool VerifyHashString(ReadOnlySpan<byte> utf8HashString, ReadOnlySpan<byte> utf8Password, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {
        ReadOnlySpan<byte> b;
        if (utf8HashString.Length == HashStringLength)
        {
            b = utf8HashString;
        }
        else
        {
            var byteArray = new byte[HashStringLength]; // Fixed size
            utf8HashString.CopyTo(byteArray);
            b = byteArray.AsSpan();
        }

        return LibsodiumInterops.crypto_pwhash_str_verify(b, utf8Password, (ulong)utf8Password.Length) == 0;
    }
}
