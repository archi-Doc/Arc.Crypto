// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class PasswordHashBenchmark
{
    public PasswordHashBenchmark()
    {
    }

    [Benchmark]
    public byte[] DeriveKey()
    {
        Span<byte> salt16 = stackalloc byte[CryptoPasswordHash.SaltSize];
        CryptoRandom.NextBytes(salt16);
        var key16 = new byte[16];
        CryptoPasswordHash.DeriveKey("test", salt16, key16);
        return key16;
    }

    [Benchmark]
    public byte[] GetHashStringUtf8()
    {
        ReadOnlySpan<byte> utf8 = [0, 1, 2, 3,];
        var st = CryptoPasswordHash.GetHashString(utf8);
        return st;
    }

    [Benchmark]
    public string GetHashString()
    {
        var st = CryptoPasswordHash.GetHashString("test");
        return st;
    }

    [Benchmark]
    public bool GetAndVerifyHashString()
    {
        var st = CryptoPasswordHash.GetHashString("test");
        var result = CryptoPasswordHash.VerifyHashString(st, "test");
        return result;
    }
}
