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
/// Represents a class which encrypts data with a password.<br/>
/// Since <see cref="PasswordEncrypt"/> uses SHA3, it's inappropriate for password authentication.<br/>
/// SHA3-384(Salt(8) + Password(n) + Previous Hash(48)) x Stretching => AES Key(32), IV(16).
/// </summary>
public static class PasswordEncrypt
{
    public const int DefaultStretchingCount = 32;
    public const int SaltLength = 8;
    public const PaddingMode DefaultPaddingMode = PaddingMode.PKCS7;

    public static byte[] Encrypt(byte[] data, string password) => Encrypt(data, Encoding.UTF8.GetBytes(password));

    public static byte[] Encrypt(byte[] data, byte[] password)
    {
        // Salt: Random[SaltLength]
        var salt = RandomNumberGenerator.GetBytes(SaltLength);

        // Hash: Sha3_384 => Key(32) + IV(16)
        var keyIV = GetKeyIV(salt, password);

        // Checksum: FarmHash64
        var checksum = FarmHash.Hash64(data);

        // AES
        var aes = Aes.Create();
        aes.Key = keyIV.Slice(0, aes.KeySize / 8).ToArray();
        var plainLength = sizeof(ulong) + data.Length;
        var cipherLength = aes.GetCiphertextLengthCbc(plainLength, PaddingMode.PKCS7);
        if (keyIV.Length != ((aes.KeySize / 8) + (aes.BlockSize / 8)))
        {
            throw new InvalidOperationException();
        }

        // Salt(8), Encrypted(n) [Checksum(8), Data(n - 8)]
        var bufferPosition = 0;
        var bufferLength = SaltLength + cipherLength;
        var buffer = new byte[bufferLength];
        Array.Copy(salt, 0, buffer, 0, SaltLength);
        bufferPosition += SaltLength;
        BitConverter.TryWriteBytes(buffer.AsSpan(bufferPosition), checksum);
        bufferPosition += sizeof(ulong);
        Array.Copy(data, 0, buffer, bufferPosition, data.Length);

        // var iv = new byte[16];
        // Array.Copy(previousHash, 32, iv, 0, 16);
        // aes.IV = iv;
        // var e = aes.CreateEncryptor(keyIV.Slice(0, aes.KeySize / 8).ToArray(), keyIV.Slice(aes.KeySize / 8).ToArray());
        var written = aes.EncryptCbc(buffer.AsSpan(SaltLength, plainLength), keyIV.Slice(aes.KeySize / 8), buffer.AsSpan(SaltLength), DefaultPaddingMode);
        Debug.Assert(written == cipherLength, "Encrypted length mismatch.");

        return buffer;
    }

    public static bool TryDecrypt(byte[] encrypted, string password, out Memory<byte> data) => TryDecrypt(encrypted, Encoding.UTF8.GetBytes(password), out data);

    public static bool TryDecrypt(byte[] encrypted, byte[] password, out Memory<byte> data)
    {// [MaybeNullWhen(false)]
        data = default;
        if (encrypted.Length < SaltLength)
        {
            return false;
        }

        // Hash: Sha3_384 => Key(32) + IV(16)
        var keyIV = GetKeyIV(encrypted, password);

        // AES
        var aes = Aes.Create();
        aes.Key = keyIV.Slice(0, aes.KeySize / 8).ToArray();
        if (keyIV.Length != ((aes.KeySize / 8) + (aes.BlockSize / 8)))
        {
            throw new InvalidOperationException();
        }

        var decrypted = aes.DecryptCbc(encrypted.AsSpan(sizeof(ulong)), keyIV.Slice(aes.KeySize / 8), DefaultPaddingMode);
        if (decrypted.Length < sizeof(ulong))
        {
            return false;
        }

        // Checksum: FarmHash64
        var checksum = FarmHash.Hash64(decrypted.AsSpan(sizeof(ulong)));
        if (BitConverter.ToUInt64(decrypted) != checksum)
        {
            return false;
        }

        data = decrypted.AsMemory(sizeof(ulong));

        return true;
    }

    public static int StretchingCount
    {
        get => stretchingCount;
        set
        {
            if (value <= 0)
            {
                throw new InvalidOperationException("StretchingCount must be greater than 0.");
            }

            stretchingCount = value;
        }
    }

    private static Span<byte> GetKeyIV(byte[] salt, byte[] password)
    {
        // Hash: Sha3_384
        var hash = new Sha3_384();
        var hashLength = hash.HashBytes;

        // SHA3-384(Salt(8) + Password(n) + Previous Hash(48)) x StretchingCount => AES Key(32), IV(16).
        var bufferPosition = 0;
        var bufferLength = SaltLength + password.Length + hashLength;
        var buffer = new byte[bufferLength];
        Array.Copy(salt, 0, buffer, 0, SaltLength);
        bufferPosition += SaltLength;
        Array.Copy(password, 0, buffer, bufferPosition, password.Length);
        bufferPosition += password.Length;

        var hashSpan = buffer.AsSpan(bufferPosition);
        for (var i = 0; i < StretchingCount; i++)
        {
            hash.GetHash(buffer, hashSpan);
            // Array.Copy(previousHash, 0, buffer, bufferPosition, hashLength);
        }

        return hashSpan;
    }

    private static int stretchingCount = DefaultStretchingCount;
}
