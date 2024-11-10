// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Text;

namespace Arc.Crypto;

public static class CryptoPasswordHash
{
    public const int SaltBytes = 16; // crypto_pwhash_SALTBYTES crypto_pwhash_argon2id_SALTBYTES
    public const int DefaultAlgorithm = 2; // crypto_pwhash_ALG_DEFAULT crypto_pwhash_ALG_ARGON2ID13 crypto_pwhash_argon2id_ALG_ARGON2ID13

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

    public static void DeriveKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt16, Span<byte> @out, ulong outLength, OpsLimit opsLimit = OpsLimit.Interactive, MemLimit memLimit = MemLimit.Interactive)
    {// CryptoHelper.ThrowSizeMismatchException(nameof(output), Size);
        var utf8 = Encoding.UTF8.GetBytes("test");
        LibsodiumInterops.crypto_pwhash(@out, outLength, utf8, (ulong)utf8.Length, salt16, (ulong)opsLimit, (UIntPtr)memLimit, DefaultAlgorithm);
    }
}
