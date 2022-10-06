// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

#pragma warning disable SA1310 // Field names should not contain underscore
#pragma warning disable CS1591
#pragma warning disable SA1402
#pragma warning disable SA1600 // Elements should be documented

namespace Benchmark;

public class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Arc.Crypto Benchmark.");

        // RandomVaultBenchmark.Test1();
        DebugRun<HexStringBenchmark>();

        // var summary = BenchmarkRunner.Run<SpeedBenchmark>();
        var switcher = new BenchmarkSwitcher(new[]
        {
            typeof(HexStringBenchmark),
            typeof(RandomVaultBenchmark),
            typeof(CryptoRandomBenchmark),
            typeof(PseudoRandomBenchmark),
            typeof(HashBenchmark),
            typeof(StringBenchmark),
            typeof(Sha256Benchmark),
            typeof(SpeedBenchmark),
        });
        switcher.Run(args);
    }

    public static void DebugRun<T>()
    where T : new()
    { // Run a benchmark in debug mode.
        var t = new T();
        var type = typeof(T);
        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance);
        var fields = type.GetFields(BindingFlags.Public | BindingFlags.Instance);
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);

        foreach (var x in fields)
        { // Set Fields.
            var attr = (ParamsAttribute[])x.GetCustomAttributes(typeof(ParamsAttribute), false);
            if (attr != null && attr.Length > 0)
            {
                if (attr[0].Values.Length > 0)
                {
                    x.SetValue(t, attr[0].Values[0]);
                }
            }
        }

        foreach (var x in properties)
        { // Set Properties.
            var attr = (ParamsAttribute[])x.GetCustomAttributes(typeof(ParamsAttribute), false);
            if (attr != null && attr.Length > 0)
            {
                if (attr[0].Values.Length > 0)
                {
                    x.SetValue(t, attr[0].Values[0]);
                }
            }
        }

        foreach (var x in methods.Where(i => i.GetCustomAttributes(typeof(GlobalSetupAttribute), false).Length > 0))
        { // [GlobalSetupAttribute]
            x.Invoke(t, null);
        }

        foreach (var x in methods.Where(i => i.GetCustomAttributes(typeof(BenchmarkAttribute), false).Length > 0))
        { // [BenchmarkAttribute]
            x.Invoke(t, null);
        }

        foreach (var x in methods.Where(i => i.GetCustomAttributes(typeof(GlobalCleanupAttribute), false).Length > 0))
        { // [GlobalCleanupAttribute]
            x.Invoke(t, null);
        }

        // obsolete code:
        // methods.Where(i => i.CustomAttributes.Select(j => j.AttributeType).Contains(typeof(GlobalSetupAttribute)))
        // bool IsNullableType(Type type) => type.IsGenericType && type.GetGenericTypeDefinition().Equals(typeof(Nullable<>));
        /* var targetType = IsNullableType(x.FieldType) ? Nullable.GetUnderlyingType(x.FieldType) : x.FieldType;
                    if (targetType != null)
                    {
                        var value = Convert.ChangeType(attr[0].Values[0], targetType);
                        x.SetValue(t, value);
                    }*/
    }
}

public class BenchmarkConfig : BenchmarkDotNet.Configs.ManualConfig
{
    public BenchmarkConfig()
    {
        this.AddExporter(BenchmarkDotNet.Exporters.MarkdownExporter.GitHub);
        this.AddDiagnoser(BenchmarkDotNet.Diagnosers.MemoryDiagnoser.Default);

        // this.AddJob(BenchmarkDotNet.Jobs.Job.ShortRun);
    }
}

[Config(typeof(BenchmarkConfig))]
public class Sha3SpeedBenchmark
{// measure the time to calculate a hash of { data(N) x Repeat}.
    private const int N = 41;
    private const int Repeat = 1471;
    private readonly byte[] data;
    private IHash sha3_256;
    private IHash sha3_384;
    private IHash sha3_512;

    public Sha3SpeedBenchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);

        this.sha3_256 = new Sha3_256();
        this.sha3_384 = new Sha3_384();
        this.sha3_512 = new Sha3_512();
    }

    [Benchmark]
    public byte[] Sha3_256()
    {
        this.sha3_256.HashInitialize();
        for (var n = 0; n < Repeat; n++)
        {
            this.sha3_256.HashUpdate(this.data, 0, N);
        }

        return this.sha3_256.HashFinal();
    }

    [Benchmark]
    public byte[] Sha3_384()
    {
        this.sha3_384.HashInitialize();
        for (var n = 0; n < Repeat; n++)
        {
            this.sha3_384.HashUpdate(this.data, 0, N);
        }

        return this.sha3_384.HashFinal();
    }

    [Benchmark]
    public byte[] Sha3_512()
    {
        this.sha3_512.HashInitialize();
        for (var n = 0; n < Repeat; n++)
        {
            this.sha3_512.HashUpdate(this.data, 0, N);
        }

        return this.sha3_512.HashFinal();
    }
}

[Config(typeof(BenchmarkConfig))]
public class SpeedBenchmark
{// measure the time to calculate a hash of 1 MB data.
    private const int N = 1_000_000;
    private readonly byte[] data;
    private IHash farm;
    private IHash farmBeta;
    private IHash xxh32;
    private IHash xxh64;
    private IHash sha1;
    private IHash sha2_256;
    private IHash sha2_384;
    private IHash sha2_512;
    private IHash sha3_256;
    private IHash sha3_256ob;
    private IHash sha3_384;
    private IHash sha3_512;

    public SpeedBenchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);

        this.farm = new FarmHash();
        this.farmBeta = new Beta.Crypto.FarmHash(); // System.Numerics.BitOperation
        this.xxh32 = new XXHash32();
        this.xxh64 = new XxHash64();
        this.sha1 = new Arc.Crypto.Sha1();
        this.sha2_256 = new Sha2_256();
        this.sha2_384 = new Sha2_384();
        this.sha2_512 = new Sha2_512();
        this.sha3_256 = new Sha3_256();
        this.sha3_256ob = new Obsolete.Sha3_256();
        this.sha3_384 = new Sha3_384();
        this.sha3_512 = new Sha3_512();
    }

    [Benchmark]
    public byte[] FarmHash64() => this.farm.GetHash(this.data);

    /*[Benchmark]
    public byte[] FarmHash64Beta() => this.farmBeta.GetHash(this.data);

    [Benchmark]
    public byte[] XxHash32() => this.xxh32.GetHash(this.data);

    [Benchmark]
    public byte[] XxHash64() => this.xxh64.GetHash(this.data);

    [Benchmark]
    public byte[] Sha1() => this.sha1.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] ShaA2_256() => this.sha2_256.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] Sha2_384() => this.sha2_384.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] Sha2_512() => this.sha2_512.GetHash(this.data, 0, this.data.Length);*/

    [Benchmark]
    public byte[] Sha3_256() => this.sha3_256.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] Sha3_256Ob() => this.sha3_256ob.GetHash(this.data, 0, this.data.Length);

    /*[Benchmark]
    public byte[] Sha3_384() => this.sha3_384.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] Sha3_512() => this.sha3_512.GetHash(this.data, 0, this.data.Length);*/
}

[Config(typeof(BenchmarkConfig))]
public class Sha256Benchmark
{// measure the time to calculate a hash of 1 MB data. Sha256/Managed/ServiceProvider.
    private const int N = 1_000_000;
    private readonly byte[] data;

    private HashAlgorithm sha256;
    private HashAlgorithm sha256Managed;
    private HashAlgorithm sha256ServiceProvider;

    public Sha256Benchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);

        this.sha256 = System.Security.Cryptography.SHA256.Create();
#pragma warning disable SYSLIB0021 // Type or member is obsolete
        this.sha256Managed = System.Security.Cryptography.SHA256Managed.Create();
        this.sha256ServiceProvider = new SHA256CryptoServiceProvider();
#pragma warning restore SYSLIB0021 // Type or member is obsolete
    }

    [Params(10, 1_000, 1_000_000)]
    public int Length { get; set; }

    [Benchmark]
    public byte[] Sha256() => this.sha256.ComputeHash(this.data, 0, this.Length);

    [Benchmark]
    public byte[] Sha256Managed() => this.sha256Managed.ComputeHash(this.data, 0, this.Length);

    [Benchmark]
    public byte[] Sha256ServiceProvider() => this.sha256ServiceProvider.ComputeHash(this.data, 0, this.Length);
}

[Config(typeof(BenchmarkConfig))]
public class StringBenchmark
{// measure the time to calculate a hash of the string.
    private const string TestString = "0123456789ABCDEF0123456789ABCDEF";

    [Benchmark]
    public int String_GetHashCode() => TestString.GetHashCode();

    [Benchmark]
    public uint ArcFarmHash32_Direct() => Arc.Crypto.FarmHash.Hash32(TestString);

    [Benchmark]
    public uint ArcFarmHash32_64to32() => unchecked((uint)Arc.Crypto.FarmHash.Hash64(TestString));

    [Benchmark]
    public ulong ArcFarmHash64_Direct() => Arc.Crypto.FarmHash.Hash64(TestString);

    /*[Benchmark]
    public ulong ArcFarmHash64_GetBytes() => Arc.Crypto.FarmHash.Hash64(Encoding.UTF8.GetBytes(TestString));

    [Benchmark]
    public uint ArcXXHash32_Direct() => Arc.Crypto.XXHash32.Hash32(TestString);

    [Benchmark]
    public ulong ArcXxHash64_Direct() => Arc.Crypto.XxHash64.Hash64(TestString);*/
}

[Config(typeof(BenchmarkConfig))]
public class HashBenchmark
{
    private const int N = 1_000_000;
    private readonly byte[] data;
    private FarmHash farm;
    private XXHash32 xxh32;
    private XxHash64 xxh64;

    public HashBenchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);
        this.farm = new FarmHash();
        this.xxh32 = new XXHash32();
        this.xxh64 = new XxHash64();
    }

    [Params(10, 100, 200, 1000, 1_000_000)]
    public int Length { get; set; }

    [Benchmark]
    public ulong ArcFarmHash64() => Arc.Crypto.FarmHash.Hash64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public byte[] ArcFarmHash64_IHash()
    {
        this.farm.HashInitialize();
        this.farm.HashUpdate(this.data.AsSpan(0, this.Length));
        return this.farm.HashFinal();
    }

    [Benchmark]
    public uint ArcXXHash32() => Arc.Crypto.XXHash32.Hash32(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public byte[] ArcXXHash32_IHash()
    {
        this.xxh32.HashInitialize();
        this.xxh32.HashUpdate(this.data.AsSpan(0, this.Length));
        return this.xxh32.HashFinal();
    }

    [Benchmark]
    public ulong ArcXxHash64() => Arc.Crypto.XxHash64.Hash64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public byte[] ArcXxHash64_IHash()
    {
        this.xxh64.HashInitialize();
        this.xxh64.HashUpdate(this.data.AsSpan(0, this.Length));
        return this.xxh64.HashFinal();
    }

    [Benchmark]
    public ulong ArcFarmHash32() => Arc.Crypto.FarmHash.Hash32(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong ArcAdler32() => Arc.Crypto.Adler32.Hash32(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong ArcCrc32() => Arc.Crypto.Crc32.Hash32(this.data.AsSpan(0, this.Length));
}
