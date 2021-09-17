// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Linq;
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

namespace Benchmark
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Arc.Crypto Benchmark.");

            // var summary = BenchmarkRunner.Run<SpeedBenchmark>();
            var switcher = new BenchmarkSwitcher(new[]
            {
                typeof(HashInstanceBenchmark),
                typeof(HashBenchmark),
                typeof(StringBenchmark),
                typeof(SHA256Benchmark),
                typeof(SpeedBenchmark),
            });
            switcher.Run(args);
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
    public class SHA3SpeedBenchmark
    {// measure the time to calculate a hash of { data(N) x Repeat}.
        private const int N = 41;
        private const int Repeat = 1471;
        private readonly byte[] data;
        private IHash sha3_256;
        private IHash sha3_384;
        private IHash sha3_512;

        public SHA3SpeedBenchmark()
        {
            this.data = new byte[N];
            new Random(42).NextBytes(this.data);

            this.sha3_256 = new SHA3_256();
            this.sha3_384 = new SHA3_384();
            this.sha3_512 = new SHA3_512();
        }

        [Benchmark]
        public byte[] SHA3_256()
        {
            this.sha3_256.HashInitialize();
            for (var n = 0; n < Repeat; n++)
            {
                this.sha3_256.HashUpdate(this.data, 0, N);
            }

            return this.sha3_256.HashFinal();
        }

        [Benchmark]
        public byte[] SHA3_384()
        {
            this.sha3_384.HashInitialize();
            for (var n = 0; n < Repeat; n++)
            {
                this.sha3_384.HashUpdate(this.data, 0, N);
            }

            return this.sha3_384.HashFinal();
        }

        [Benchmark]
        public byte[] SHA3_512()
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
        private IHash sha3_384;
        private IHash sha3_512;

        public SpeedBenchmark()
        {
            this.data = new byte[N];
            new Random(42).NextBytes(this.data);

            this.farm = new FarmHash();
            this.farmBeta = new Beta.Crypto.FarmHash(); // System.Numerics.BitOperation
            this.xxh32 = new XXHash32();
            this.xxh64 = new XXHash64();
            this.sha1 = new Arc.Crypto.SHA1();
            this.sha2_256 = new SHA2_256();
            this.sha2_384 = new SHA2_384();
            this.sha2_512 = new SHA2_512();
            this.sha3_256 = new SHA3_256();
            this.sha3_384 = new SHA3_384();
            this.sha3_512 = new SHA3_512();
        }

        [Benchmark]
        public byte[] FarmHash64() => this.farm.GetHash(this.data);

        [Benchmark]
        public byte[] FarmHash64Beta() => this.farmBeta.GetHash(this.data);

        [Benchmark]
        public byte[] XXHash32() => this.xxh32.GetHash(this.data);

        [Benchmark]
        public byte[] XXHash64() => this.xxh64.GetHash(this.data);

        [Benchmark]
        public byte[] SHA1() => this.sha1.GetHash(this.data, 0, this.data.Length);

        [Benchmark]
        public byte[] SHA2_256() => this.sha2_256.GetHash(this.data, 0, this.data.Length);

        [Benchmark]
        public byte[] SHA2_384() => this.sha2_384.GetHash(this.data, 0, this.data.Length);

        [Benchmark]
        public byte[] SHA2_512() => this.sha2_512.GetHash(this.data, 0, this.data.Length);

        [Benchmark]
        public byte[] SHA3_256() => this.sha3_256.GetHash(this.data, 0, this.data.Length);

        [Benchmark]
        public byte[] SHA3_384() => this.sha3_384.GetHash(this.data, 0, this.data.Length);

        [Benchmark]
        public byte[] SHA3_512() => this.sha3_512.GetHash(this.data, 0, this.data.Length);
    }

    [Config(typeof(BenchmarkConfig))]
    public class SHA256Benchmark
    {// measure the time to calculate a hash of 1 MB data. SHA256/Managed/ServiceProvider.
        private const int N = 1_000_000;
        private readonly byte[] data;

        private HashAlgorithm sha256;
        private HashAlgorithm sha256Managed;
        private HashAlgorithm sha256ServiceProvider;

        public SHA256Benchmark()
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
        public byte[] SHA256() => this.sha256.ComputeHash(this.data, 0, this.Length);

        [Benchmark]
        public byte[] SHA256Managed() => this.sha256Managed.ComputeHash(this.data, 0, this.Length);

        [Benchmark]
        public byte[] SHA256ServiceProvider() => this.sha256ServiceProvider.ComputeHash(this.data, 0, this.Length);
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
        public ulong ArcXXHash64_Direct() => Arc.Crypto.XXHash64.Hash64(TestString);*/
    }

    [Config(typeof(BenchmarkConfig))]
    public class HashBenchmark
    {
        private const int N = 1_000_000;
        private readonly byte[] data;
        private FarmHash farm;
        private XXHash32 xxh32;
        private XXHash64 xxh64;

        public HashBenchmark()
        {
            this.data = new byte[N];
            new Random(42).NextBytes(this.data);
            this.farm = new FarmHash();
            this.xxh32 = new XXHash32();
            this.xxh64 = new XXHash64();
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
        public ulong ArcXXHash64() => Arc.Crypto.XXHash64.Hash64(this.data.AsSpan(0, this.Length));

        [Benchmark]
        public byte[] ArcXXHash64_IHash()
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
        public ulong ArcCRC32() => Arc.Crypto.CRC32.Hash32(this.data.AsSpan(0, this.Length));
    }
}
