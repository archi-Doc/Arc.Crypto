// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;
using static FastExpressionCompiler.ExpressionCompiler;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class CipherBenchmark
{
    private const int Length = 1008;//1000;
    private readonly byte[] message;
    private readonly byte[] message2;
    private readonly byte[] cipher;
    private readonly byte[] cipher2;
    private readonly byte[] cipherAes;
    private readonly byte[] cipherAes2;
    private readonly byte[] cipherXChacha20;
    private readonly byte[] key;
    private readonly byte[] nonce;
    private readonly Aes aes;

    public CipherBenchmark()
    {
        var random = new Xoshiro256StarStar(12);

        this.message = new byte[Length];
        for (var i = 0; i < this.message.Length; i++)
        {
            this.message[i] = (byte)(i & 255);
        }

        this.message2 = new byte[Length];

        this.key = new byte[32];
        CryptoBoxHelper.CreateKey(this.key);
        this.nonce = new byte[24];
        random.NextBytes(this.nonce);
        this.cipher = new byte[this.message.Length + CryptoBoxHelper.MacSizeInBytes];
        this.cipher2 = new byte[this.message.Length + CryptoBoxHelper.MacSizeInBytes];
        CryptoBoxHelper.Encrypt(this.message, this.nonce, this.key, this.cipher);

        this.aes = Aes.Create();
        this.aes.KeySize = 256;
        this.aes.Key = this.key;
        this.cipherAes = new byte[this.message.Length + 16];
        this.cipherAes2 = new byte[this.message.Length + 16];
        var result = this.aes.TryEncryptCbc(this.message, this.nonce.AsSpan(0, 16), this.cipherAes, out var written, PaddingMode.PKCS7);

        this.cipherXChacha20 = new byte[this.message.Length];
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
        CryptoBoxHelper.CreateKey(key);
        return key;
    }

    [Benchmark]
    public byte[] crypto_secretbox_encrypt()
    {
        // var c = new byte[this.message.Length + CryptoBoxHelper.MacSizeInBytes];
        CryptoBoxHelper.Encrypt(this.message, this.nonce, this.key, this.cipher2);
        return this.cipher2;
    }

    [Benchmark]
    public byte[] AesEncrypt()
    {
        this.aes.TryEncryptCbc(this.message, this.nonce.AsSpan(0, 16), this.cipherAes2, out var written, PaddingMode.PKCS7);
        return this.cipherAes2;
    }

    [Benchmark]
    public byte[] AesEncrypt2()
    {
        this.aes.TryEncryptCbc(this.message, this.nonce.AsSpan(0, 16), this.cipherAes2, out var written, PaddingMode.None);
        return this.cipherAes2;
    }

    [Benchmark]
    public byte[] XChacha20Xor()
    {
        XChaCha20.Xor(this.message, this.nonce, this.key, this.cipherXChacha20);
        return this.cipherXChacha20;
    }

    [Benchmark]
    public byte[] Chacha20Xor()
    {
        XChaCha20.Xor2(this.message, this.nonce, this.key, this.cipherXChacha20);
        return this.cipherXChacha20;
    }

    [Benchmark]
    public byte[] crypto_secretbox_decrypt()
    {
        // var m = new byte[this.message.Length];
        CryptoBoxHelper.Decrypt(this.cipher, this.nonce, this.key, this.message2);
        return this.message2;
    }

    [Benchmark]
    public byte[] AesDecrypt()
    {
        this.aes.TryDecryptCbc(this.cipherAes, this.nonce.AsSpan(0, 16), this.message2, out var written, PaddingMode.PKCS7);
        return this.message2;
    }
}
