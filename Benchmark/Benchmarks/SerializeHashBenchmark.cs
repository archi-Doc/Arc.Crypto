// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;
using Tinyhand;

namespace Benchmark;

/*[TinyhandObject]
public partial class SerializeHashClass
{// Slightly faster
    public SerializeHashClass()
    {
    }

    public SerializeHashClass(byte[] data)
    {
        this.Data = data;
    }

    public void PrepareHash()
    {
        (this.Hash0, this.Hash1, this.Hash2, this.Hash3) = Blake3.Get256_UInt64(this.Data);
    }

    [Key(0)]
    public byte[] Data { get; set; } = default!;

    [Key(1)]
    public ulong Hash0 { get; set; }

    [Key(2)]
    public ulong Hash1 { get; set; }

    [Key(3)]
    public ulong Hash2 { get; set; }

    [Key(4)]
    public ulong Hash3 { get; set; }
}

[TinyhandObject]
public partial class SerializeHashClass2
{
    public SerializeHashClass2()
    {
    }

    public SerializeHashClass2(byte[] data)
    {
        this.Data = data;
    }

    public void PrepareHash()
    {
        this.Hash = Blake3.Get256_Struct(this.Data);
    }

    [Key(0)]
    public byte[] Data { get; set; } = default!;

    [Key(1)]
    public Struct256 Hash { get; set; }
}

[Config(typeof(BenchmarkConfig))]
public class SerializeHashBenchmark
{
    private readonly byte[] data;

    public SerializeHashBenchmark()
    {
        this.data = new byte[100];
        RandomVault.Pseudo.NextBytes(this.data);
    }

    [Benchmark]
    public bool Test1()
    {
        var tc = new SerializeHashClass(this.data);
        tc.PrepareHash();

        var tc2 = TinyhandSerializer.Deserialize<SerializeHashClass>(TinyhandSerializer.Serialize(tc))!;
        tc2.PrepareHash();

        var b = tc.Hash0 == tc2.Hash0 && tc.Hash1 == tc2.Hash1 && tc.Hash2 == tc2.Hash2 && tc.Hash3 == tc2.Hash3;
        return b;
    }

    [Benchmark]
    public bool Test2()
    {
        var tc = new SerializeHashClass2(this.data);
        tc.PrepareHash();

        var tc2 = TinyhandSerializer.Deserialize<SerializeHashClass2>(TinyhandSerializer.Serialize(tc))!;
        tc2.PrepareHash();

        var b = tc.Hash.Equals(tc2.Hash);
        return b;
    }
}*/
