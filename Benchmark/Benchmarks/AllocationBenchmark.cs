// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using Arc.Crypto.EC;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class AllocationBenchmark
{
    private readonly byte[] data = new byte[4096];
    private readonly byte[] hash = new byte[32];
    private readonly byte[] cipher = new byte[48];

    [GlobalSetup]
    public void Setup() => new Random(42).NextBytes(this.data);

    [Benchmark]
    public bool SeedValidation() => P256K1Curve.Instance.IsValidSeed(this.data.AsSpan(0, 32));

    [Benchmark]
    public string Base32Short() => Base32Sort.Default.FromByteArrayToString(this.data.AsSpan(0, 32));

    [Benchmark]
    public string Base32Long() => Base32Sort.Default.FromByteArrayToString(this.data);

    [Benchmark]
    public void Sha256Span() => Sha2Helper.Get256_Span(this.data.AsSpan(0, 32), this.hash);

    [Benchmark]
    public void Sha3Tail() => Sha3Helper.Get256_Span(this.data.AsSpan(0, 135), this.hash);

    [Benchmark]
    public void PasswordSpan() => PasswordEncryption.Encrypt(ReadOnlySpan<byte>.Empty, "password", this.cipher);
}
