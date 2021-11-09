// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
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

    public static byte[] Encrypt(byte[] data, string password) => Encrypt(data, Encoding.UTF8.GetBytes(password));

    public static byte[] Encrypt(byte[] data, byte[] password)
    {
        // Hash: Sha3_384
        var hash = new Sha3_384();
        var hashLength = hash.HashBytes;

        // Checksum: FarmHash64
        var checksum = FarmHash.Hash64(data);

        // Salt: Random[SaltLength]
        var salt = RandomNumberGenerator.GetBytes(SaltLength);

        // SHA3-384(Salt(8) + Password(n) + Previous Hash(48)) x StretchingCount => AES Key(32), IV(16).
        var bufferPosition = 0;
        var bufferLength = SaltLength + password.Length + hashLength;
        var buffer = new byte[bufferLength];
        Array.Copy(salt, 0, buffer, 0, SaltLength);
        bufferPosition += SaltLength;
        Array.Copy(password, 0, buffer, bufferPosition, password.Length);
        bufferPosition += password.Length;

        var previousHash = Array.Empty<byte>();
        for (var i = 0; i < StretchingCount; i++)
        {
            previousHash = hash.GetHash(buffer);
            Array.Copy(previousHash, 0, buffer, bufferPosition, hashLength);
        }

        // Salt(8), Encrypted(n) [Checksum(8), Data(n - 8)]
        bufferPosition = 0;
        bufferLength = SaltLength + sizeof(ulong) + data.Length;
        buffer = new byte[bufferLength];
        Array.Copy(salt, 0, buffer, 0, SaltLength);
        bufferPosition += SaltLength;
        BitConverter.TryWriteBytes(buffer.AsSpan(bufferPosition), checksum);
        bufferPosition += sizeof(ulong);

        // AES
        var aes = Aes.Create();
        aes.KeySize = 32;
        aes.Key = previousHash;
        // var iv = new byte[16];
        // Array.Copy(previousHash, 32, iv, 0, 16);
        // aes.IV = iv;
        aes.EncryptCbc(data, previousHash.AsSpan(32), buffer.AsSpan(bufferPosition), PaddingMode.None);

        return buffer;
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

    private static int stretchingCount = DefaultStretchingCount;
}
