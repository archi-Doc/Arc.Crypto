// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class LibsodiumBenchmark
{
    private readonly byte[] message;
    private readonly byte[] message2;
    private readonly byte[] cipher;
    private readonly byte[] cipher2;
    private readonly byte[] key;
    private readonly byte[] nonce;

    public LibsodiumBenchmark()
    {
        var random = new Xoshiro256StarStar(12);
        this.message = [0, 1, 2, 3,];
        this.message2 = new byte[this.message.Length];

        this.key = new byte[32];
        CryptoBoxHelper.CreateKey(this.key);
        this.nonce = new byte[24];
        random.NextBytes(this.nonce);
        this.cipher = new byte[this.message.Length + CryptoBoxHelper.MacSizeInBytes];
        this.cipher2 = new byte[this.message.Length + CryptoBoxHelper.MacSizeInBytes];
        CryptoBoxHelper.Encrypt(this.message, this.nonce, this.key, this.cipher);
    }

    [Params(10)]
    public int Length { get; set; }

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
    public byte[] crypto_secretbox_decrypt()
    {
        // var m = new byte[this.message.Length];
        CryptoBoxHelper.Decrypt(this.cipher, this.nonce, this.key, this.message2);
        return this.message2;
    }
}
