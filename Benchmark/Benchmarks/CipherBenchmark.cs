// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class CipherBenchmark
{
    private const int Length = 1000;

    private readonly byte[] message;
    private readonly byte[] message2;
    private readonly byte[] cipher;
    private readonly byte[] cipher2;
    private readonly byte[] cipherAes;
    private readonly byte[] cipherAes2;
    private readonly byte[] cipherXChacha20;
    private readonly byte[] cipherAegis;
    private readonly byte[] cipherAegis2;
    private readonly byte[] cipherAegis3;
    private readonly byte[] key;
    private readonly byte[] nonce24;
    private readonly byte[] nonce32;
    private readonly byte[] tag16;
    private readonly byte[] tag32;
    private readonly Aes aes;
    private readonly byte[] messageAesNi;
    private readonly int aesSize;
    private readonly byte[] boxSecretKey;
    private readonly byte[] boxPublicKey;
    private readonly byte[] boxSecretKey2;
    private readonly byte[] boxPublicKey2;
    private readonly byte[] cipherBox;

    public CipherBenchmark()
    {
        var random = new Xoshiro256StarStar(12);

        this.message = new byte[Length];
        for (var i = 0; i < this.message.Length; i++)
        {
            this.message[i] = (byte)(i & 255);
        }

        this.message2 = new byte[Length];
        this.messageAesNi = new byte[Length];
        this.message.AsSpan().CopyTo(this.messageAesNi);

        this.key = new byte[32];
        CryptoSecretBox.CreateKey(this.key);
        this.nonce24 = new byte[24];
        random.NextBytes(this.nonce24);
        this.nonce32 = new byte[32];
        random.NextBytes(this.nonce32);
        this.cipher = new byte[this.message.Length + CryptoSecretBox.MacSize];
        this.cipher2 = new byte[this.message.Length + CryptoSecretBox.MacSize];
        CryptoSecretBox.Encrypt(this.message, this.nonce24, this.key, this.cipher);

        this.aes = Aes.Create();
        this.aes.KeySize = 256;
        this.aes.Key = this.key;
        this.cipherAes = new byte[this.message.Length + 16];
        this.cipherAes2 = new byte[this.message.Length + 16];
        var result = this.aes.TryEncryptCbc(this.message, this.nonce24.AsSpan(0, 16), this.cipherAes, out var written, PaddingMode.PKCS7);
        this.aesSize = written;

        this.cipherXChacha20 = new byte[this.message.Length];

        this.cipherAegis = new byte[this.message.Length + Aegis256Helper.ASizeInBytes];
        this.cipherAegis2 = new byte[this.message.Length + Aegis256Helper.ASizeInBytes];
        this.cipherAegis3 = new byte[this.message.Length + Aegis128L.MinTagSize];
        this.tag16 = new byte[16];
        this.tag32 = new byte[32];
        Aegis256Helper.Encrypt(this.message, this.nonce32, this.key, this.cipherAegis, out var cipherLength);
        Aegis256Helper.Decrypt(this.cipherAegis, this.nonce32, this.key, this.message2, out var messageLength);
        Aegis128L.Encrypt(this.cipherAegis3, this.message, this.nonce32.AsSpan(0, 16), this.key.AsSpan(0, 16));

        this.boxSecretKey = new byte[CryptoBox.SecretKeySize];
        this.boxPublicKey = new byte[CryptoBox.PublicKeySize];
        CryptoBox.CreateKey(this.boxSecretKey, this.boxPublicKey);
        this.boxSecretKey2 = new byte[CryptoBox.SecretKeySize];
        this.boxPublicKey2 = new byte[CryptoBox.PublicKeySize];
        CryptoBox.CreateKey(this.boxSecretKey2, this.boxPublicKey2);
        this.cipherBox = new byte[this.message.Length + CryptoBox.MacSize];
    }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public byte[] crypto_secretbox_keygen()
    {
        var key = new byte[32];
        CryptoSecretBox.CreateKey(key);
        return key;
    }

    [Benchmark]
    public byte[] crypto_secretbox_encrypt()
    {
        CryptoSecretBox.Encrypt(this.message, this.nonce24, this.key, this.cipher2);
        return this.cipher2;
    }

    [Benchmark]
    public byte[] crypto_box_encrypt_32()
    {
        CryptoBox.Encrypt(this.message.AsSpan(0, 32), this.nonce24, this.boxSecretKey, this.boxPublicKey2, this.cipherBox.AsSpan(0, 32 + CryptoBox.MacSize));
        return this.cipherBox;
    }

    [Benchmark]
    public byte[] crypto_box_encrypt()
    {
        CryptoBox.Encrypt(this.message, this.nonce24, this.boxSecretKey, this.boxPublicKey2, this.cipherBox);
        return this.cipherBox;
    }

    [Benchmark]
    public byte[] AesEncrypt()
    {
        this.aes.TryEncryptCbc(this.message, this.nonce24.AsSpan(0, 16), this.cipherAes2, out var written, PaddingMode.PKCS7);
        return this.cipherAes2;
    }

    [Benchmark]
    public byte[] XChacha20Xor()
    {
        XChaCha20.Xor(this.message, this.nonce24, this.key, this.cipherXChacha20);
        return this.cipherXChacha20;
    }

    [Benchmark]
    public byte[] Chacha20Xor()
    {
        XChaCha20.Xor2(this.message, this.nonce24, this.key, this.cipherXChacha20);
        return this.cipherXChacha20;
    }

    [Benchmark]
    public byte[] Aegis128Encrypt()
    {
        Aegis128L.Encrypt(this.cipherAegis3, this.message, this.nonce32.AsSpan(0, 16), this.key.AsSpan(0, 16));
        return this.cipherAegis3;
    }

    [Benchmark]
    public byte[] Aegis128Tag()
    {
        Aegis128L.Encrypt(this.tag16, [], this.nonce32.AsSpan(0, 16), this.key.AsSpan(0, 16), this.message, 16);
        return this.tag16;
    }

    [Benchmark]
    public byte[] Aegis256Encrypt()
    {
        Aegis256.Encrypt(this.cipherAegis2, this.message, this.nonce32, this.key, default, 32);
        return this.cipherAegis2;
    }

    // [Benchmark]
    public byte[] Aegis256Encrypt_AegisDotNet()
    {
        AegisDotNet.AEGIS256.Encrypt(this.cipherAegis2, this.message, this.nonce32, this.key, default, 32);
        return this.cipherAegis2;
    }

    [Benchmark]
    public byte[] Aegis256Encrypt_Libsodium()
    {
        Aegis256Helper.Encrypt(this.message, this.nonce32, this.key, this.cipherAegis2, out var cipherLength);
        return this.cipherAegis2;
    }

    [Benchmark]
    public byte[] crypto_secretbox_decrypt()
    {
        // var m = new byte[this.message.Length];
        var result = CryptoSecretBox.TryDecrypt(this.cipher, this.nonce24, this.key, this.message2);
        return this.message2;
    }

    [Benchmark]
    public byte[] AesDecrypt()
    {
        this.aes.TryDecryptCbc(this.cipherAes.AsSpan(0, this.aesSize), this.nonce24.AsSpan(0, 16), this.message2, out var written, PaddingMode.PKCS7);
        return this.message2;
    }

    [Benchmark]
    public byte[] Aegis128Decrypt()
    {
        Aegis128L.TryDecrypt(this.message2, this.cipherAegis3, this.nonce32.AsSpan(0, 16), this.key.AsSpan(0, 16));
        return this.message2;
    }

    [Benchmark]
    public byte[] Aegis256Decrypt()
    {
        Aegis256.TryDecrypt(this.message2, this.cipherAegis, this.nonce32, this.key, default, 32);
        return this.message2;
    }

    // [Benchmark]
    public byte[] Aegis256Decrypt_AegisDotNet()
    {
        AegisDotNet.AEGIS256.Decrypt(this.message2, this.cipherAegis, this.nonce32, this.key, default, 32);
        return this.message2;
    }

    [Benchmark]
    public byte[] Aegis256Decrypt_Libsodium()
    {
        Aegis256Helper.Decrypt(this.cipherAegis, this.nonce32, this.key, this.message2, out var messageLength);
        return this.message2;
    }
}
