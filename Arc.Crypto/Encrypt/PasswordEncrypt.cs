// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Arc.Crypto;

/// <summary>
/// Represents a class which encrypts data with the specified password.<br/>
/// Since <see cref="PasswordEncrypt"/> uses SHA3, it's inappropriate for password authentication.<br/>
/// Key: SHA3-384(Salt[8] + Password[PasswordLength] + Hash[48]) x StretchingCount => AES Key(32), IV(16).<br/>
/// Output: Salt[8], Encrypted[8 + 8 + DataLength] (Random[8], Checksum[8 = FarmHash64], Data[DataLength]).
/// </summary>
public static class PasswordEncrypt
{
    /// <summary>
    /// Encrypts data using the specified password.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password.</param>
    /// <returns>The encrypted data.</returns>
    public static byte[] Encrypt(ReadOnlySpan<byte> data, string? password) => Encrypt(data, password == null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(password));

    /// <summary>
    /// Encrypts data using the specified password.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password.</param>
    /// <returns>The encrypted data.</returns>
    public static byte[] Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> password)
    {
// Salt: Random[SaltLength], Random: Random[RandomLength]
GenerateRandom:
        var randomBuffer = RandomNumberGenerator.GetBytes(SaltLength + RandomLength);
        var salt = randomBuffer.AsSpan(0, SaltLength);
        if (password.Length == 0)
        {// NO password. Set salt 0.
            salt.Fill(0);
        }
        else
        {// salt is not 0.
            foreach (var x in salt)
            {
                if (x != 0)
                {
                    goto ValidSalt;
                }
            }

            // salt is 0. Regenerate.
            goto GenerateRandom;
        }

ValidSalt:
        var random = randomBuffer.AsSpan(SaltLength, RandomLength);

        // Hash: Sha3_384 => Key(32) + IV(16)
        var keyIV = GetKeyIV(salt, password);

        // Checksum: FarmHash64
        var checksum = FarmHash.Hash64(data);

        // AES
        var aes = Aes.Create();
        aes.Key = keyIV.Slice(0, aes.KeySize / 8).ToArray();
        var plainLength = RandomLength + ChecksumLength + data.Length;
        var cipherLength = aes.GetCiphertextLengthCbc(plainLength, DefaultPaddingMode);
        if (keyIV.Length != ((aes.KeySize / 8) + (aes.BlockSize / 8)))
        {
            throw new InvalidOperationException();
        }

        // Salt[8], Encrypted[8 + 8 + DataLength] (Random[8], Checksum[8 = FarmHash64], Data[DataLength])
        var bufferLength = SaltLength + cipherLength;
        var buffer = new byte[bufferLength];
        var bufferSpan = buffer.AsSpan();
        salt.CopyTo(bufferSpan);
        bufferSpan = bufferSpan.Slice(SaltLength);
        random.CopyTo(bufferSpan);
        bufferSpan = bufferSpan.Slice(RandomLength);
        BitConverter.TryWriteBytes(bufferSpan, checksum);
        bufferSpan = bufferSpan.Slice(ChecksumLength);
        data.CopyTo(bufferSpan);

        // Encrypt
        var written = aes.EncryptCbc(buffer.AsSpan(SaltLength, plainLength), keyIV.Slice(aes.KeySize / 8), buffer.AsSpan(SaltLength), DefaultPaddingMode);
        Debug.Assert(written == cipherLength, "Encrypted length mismatch.");

        return buffer;
    }

    /// <summary>
    /// Determines if the data is encrypted with a password.
    /// </summary>
    /// <param name="encrypted">The data.</param>
    /// <returns><see langword="true"/> if the data is encrypted; otherwise (not encrypted or invalid data), <see langword="false"/>.</returns>
    public static bool IsEncryptedWithPassword(ReadOnlySpan<byte> encrypted)
    {
        if (encrypted.Length < SaltLength)
        {
            return false;
        }

        var salt = encrypted.Slice(SaltLength);
        foreach (var x in salt)
        {
            if (x != 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Decrypts data using the specified password.
    /// </summary>
    /// <param name="encrypted">The encrypted data.</param>
    /// <param name="password">The password.</param>
    /// <param name="data">The decrypted data.</param>
    /// <returns><see langword="true"/> if the decryption was successful; otherwise, <see langword="false"/>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> encrypted, string? password, out Memory<byte> data) => TryDecrypt(encrypted, password == null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(password), out data);

    /// <summary>
    /// Decrypts data using the specified password.
    /// </summary>
    /// <param name="encrypted">The encrypted data.</param>
    /// <param name="password">The password.</param>
    /// <param name="data">The decrypted data.</param>
    /// <returns><see langword="true"/> if the decryption was successful; otherwise, <see langword="false"/>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> password, out Memory<byte> data)
    {
        data = default;
        if (encrypted.Length < SaltLength)
        {
            return false;
        }
        else if (IsEncryptedWithPassword(encrypted))
        {// NO password.
            password = Array.Empty<byte>();
        }

        // Hash: Sha3_384 => Key(32) + IV(16)
        var keyIV = GetKeyIV(encrypted.Slice(0, SaltLength), password);

        // AES
        var aes = Aes.Create();
        aes.Key = keyIV.Slice(0, aes.KeySize / 8).ToArray();
        if (keyIV.Length != ((aes.KeySize / 8) + (aes.BlockSize / 8)))
        {
            throw new InvalidOperationException();
        }

        // Salt[8], Encrypted[8 + 8 + DataLength] (Random[8], Checksum[8 = FarmHash64], Data[DataLength])
        byte[] decrypted;
        try
        {
            decrypted = aes.DecryptCbc(encrypted.Slice(SaltLength), keyIV.Slice(aes.KeySize / 8), DefaultPaddingMode);
        }
        catch
        {
            return false;
        }

        var dataPosition = RandomLength + ChecksumLength;
        if (decrypted.Length < dataPosition)
        {
            return false;
        }

        // Checksum: FarmHash64
        var checksum = FarmHash.Hash64(decrypted.AsSpan(dataPosition));
        if (BitConverter.ToUInt64(decrypted.AsSpan(RandomLength)) != checksum)
        {
            return false;
        }

        data = decrypted.AsMemory(dataPosition);
        return true;
    }

    private static Span<byte> GetKeyIV(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> password)
    {
        // Hash: Sha3_384
        var hash = new Sha3_384();

        // SHA3-384(Salt[8] + Password[PasswordLength] + Previous Hash[48]) x StretchingCount => AES Key(32), IV(16).
        var bufferLength = SaltLength + password.Length + hash.HashBytes;
        var buffer = new byte[bufferLength];
        var bufferSpan = buffer.AsSpan();
        salt.CopyTo(bufferSpan);
        bufferSpan = bufferSpan.Slice(SaltLength);
        password.CopyTo(bufferSpan);
        bufferSpan = bufferSpan.Slice(password.Length);

        var hashSpan = bufferSpan;
        for (var i = 0; i < StretchingCount; i++)
        {
            hash.GetHash(buffer, hashSpan);
        }

        return hashSpan;
    }

    private const int StretchingCount = 4;
    private const int SaltLength = 8;
    private const int RandomLength = 8;
    private const int ChecksumLength = 8;
    private const PaddingMode DefaultPaddingMode = PaddingMode.PKCS7;
}
