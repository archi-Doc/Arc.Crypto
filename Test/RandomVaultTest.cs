// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access
#pragma warning disable SA1649 // File name should match first type name

namespace Test;

internal class SerialNumberGenerator
{
    // Byte i of the stream is the low byte of fmix32(i) (MurmurHash3 finalizer).
    // Unlike a byte counter, the stream has no short period, so a skipped or repeated block of any length changes the output.
    private uint position;

    public SerialNumberGenerator()
    {
    }

    public void NextBytes(Span<byte> buffer)
    {
        for (var i = 0; i < buffer.Length; i++)
        {
            var h = this.position++;
            h ^= h >> 16;
            h *= 0x85EBCA6Bu;
            h ^= h >> 13;
            h *= 0xC2B2AE35u;
            h ^= h >> 16;
            buffer[i] = (byte)h;
        }
    }

    public void Reset()
        => this.position = 0;
}

public class RandomVaultTest
{
    [Fact]
    public void BoundaryTest()
    {
        const int Length = 10_000 * sizeof(ulong);
        const int Threshold = 32;
        var s = new SerialNumberGenerator();
        var r = new Xoshiro256StarStar(12);
        RandomVault vault;
        var buffer = new byte[Length].AsSpan();
        Span<byte> b;

        var reference = new byte[Length].AsSpan();
        s.NextBytes(reference);

        s.Reset(); // Reset
        vault = new RandomVault(x => s.NextBytes(x), Threshold);
        vault.NextBytes(buffer);
        buffer.SequenceEqual(reference).IsTrue();

        s.Reset(); // Reset
        vault = new RandomVault(x => s.NextBytes(x), Threshold);
        b = buffer;
        for (var i = 0; i < (Length / sizeof(ulong)); i++)
        {
            MemoryMarshal.Write(b, vault.NextUInt64());
            b = b.Slice(sizeof(ulong));
        }

        buffer.SequenceEqual(reference).IsTrue();

        for (var i = 0; i < 100; i++)
        {
            s.Reset(); // Reset
            vault = new RandomVault(x => s.NextBytes(x), Threshold);
            b = buffer;
            while (b.Length > 0)
            {
                if (b.Length >= sizeof(ulong) && r.NextDouble() > 0.5d)
                {// NextUInt64
                    MemoryMarshal.Write(b, vault.NextUInt64());
                    b = b.Slice(sizeof(ulong));
                }
                else
                {// NextBytes
                    var size = r.NextInt32(40);
                    var n = Math.Min(b.Length, size);
                    vault.NextBytes(b.Slice(0, n));
                    b = b.Slice(n);
                }
            }

            buffer.SequenceEqual(reference).IsTrue();
        }
    }

    [Fact]
    public void Test1()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(x => xo.NextBytes(x));

        DoubleToString(rv.NextDouble()).Is("0.0838629710598822");
        DoubleToString(rv.NextDouble()).Is("0.3789802506626686");
        DoubleToString(rv.NextDouble()).Is("0.6800434110281394");
        DoubleToString(rv.NextDouble()).Is("0.9246929453253876");
        DoubleToString(rv.NextDouble()).Is("0.9918039142821028");

        string DoubleToString(double d) => d.ToString("F16");

        rv.NextUInt64().Is(14199186830065750584ul);
        rv.NextUInt64().Is(13267978908934200754ul);
        rv.NextUInt64().Is(15679888225317814407ul);
        rv.NextUInt64().Is(14044878350692344958ul);
        rv.NextUInt64().Is(10760895422300929085ul);

        // NextBytes only
        xo = new Xoshiro256StarStar(42);
        rv = new RandomVault(x => xo.NextBytes(x));

        Span<byte> eight = stackalloc byte[sizeof(ulong)];
        DoubleToString(NextDouble(eight)).Is("0.0838629710598822");
        DoubleToString(NextDouble(eight)).Is("0.3789802506626686");
        DoubleToString(NextDouble(eight)).Is("0.6800434110281394");
        DoubleToString(NextDouble(eight)).Is("0.9246929453253876");
        DoubleToString(NextDouble(eight)).Is("0.9918039142821028");

        var bytes = new byte[5 * sizeof(ulong)];
        rv.NextBytes(bytes.AsSpan(0, 3)); // Split requests must continue the same byte stream.
        rv.NextBytes(bytes.AsSpan(3));
        var words = MemoryMarshal.Cast<byte, ulong>(bytes);
        words[0].Is(14199186830065750584ul);
        words[1].Is(13267978908934200754ul);
        words[2].Is(15679888225317814407ul);
        words[3].Is(14044878350692344958ul);
        words[4].Is(10760895422300929085ul);

        double NextDouble(Span<byte> span)
        {
            rv.NextBytes(span);
            return (MemoryMarshal.Read<ulong>(span) >> 11) * (1.0 / 9007199254740992.0);
        }

        // Multi-thread
        var xo2 = new Xoshiro256StarStar(42);
        var rv2 = new RandomVault(x => xo2.NextBytes(x));

        const int P = 100;
        const int N = 1000;
        var array = new Queue<ulong>[P];
        var t = Parallel.For(0, P, x =>
        {
            var queue = new Queue<ulong>();
            for (var i = 0; i < N; i++)
            {
                queue.Enqueue(rv2.NextUInt64());
            }

            array[x] = queue;
        });

        var ss = new SortedSet<ulong>();
        for (var i = 0; i < P; i++)
        {
            array[i].Count.Is(N);
            while (array[i].TryDequeue(out var u))
            {
                ss.Contains(u).IsFalse();
                ss.Add(u);
            }
        }

        ss.Count.Is(P * N);
    }

    [Fact]
    public void ConcurrentNextBytesAndNextUInt64DeliverEachWordOnce()
    {
        // The generator writes a counter into each 8-byte word and is not thread-safe by itself.
        // Every request below is a multiple of 8 bytes, so each delivered word is one counter value.
        // Sizes above the default threshold (256) take the direct path, the others are served from the buffer.
        ulong counter = 0;
        var vault = new RandomVault(x =>
        {
            var w = MemoryMarshal.Cast<byte, ulong>(x);
            for (var i = 0; i < w.Length; i++)
            {
                w[i] = counter++;
            }
        });

        const int Threads = 8;
        const int Iterations = 300;
        int[] sizes = [0, 8, 64, 256, 264, 4096, 8192];
        var results = new List<ulong>[Threads];
        Parallel.For(0, Threads, new ParallelOptions { MaxDegreeOfParallelism = Threads }, t =>
        {
            var random = new Xoshiro256StarStar((ulong)t + 1);
            var list = new List<ulong>();
            var buffer = new byte[8192];
            for (var i = 0; i < Iterations; i++)
            {
                var choice = random.NextInt32(sizes.Length + 1);
                if (choice == sizes.Length)
                {
                    list.Add(vault.NextUInt64());
                }
                else
                {
                    var span = buffer.AsSpan(0, sizes[choice]);
                    vault.NextBytes(span);
                    list.AddRange(MemoryMarshal.Cast<byte, ulong>(span));
                }
            }

            results[t] = list;
        });

        // The expected number of words per thread is fixed by the per-thread seeds.
        var expected = 0;
        for (var t = 0; t < Threads; t++)
        {
            var random = new Xoshiro256StarStar((ulong)t + 1);
            for (var i = 0; i < Iterations; i++)
            {
                var choice = random.NextInt32(sizes.Length + 1);
                expected += choice == sizes.Length ? 1 : sizes[choice] / sizeof(ulong);
            }
        }

        var all = results.SelectMany(x => x).ToArray();
        all.Length.Is(expected);
        all.Distinct().Count().Is(expected);
        all.All(x => x < counter).IsTrue();

        // Words that were generated but not delivered are still buffered (at most one buffer).
        Assert.InRange((long)counter - expected, 0, vault.BufferSize / sizeof(ulong));
    }

    [Fact]
    public void ThresholdIsCappedAtBufferSize()
    {
        var reference = new byte[20_000];
        var s = new SerialNumberGenerator();
        s.NextBytes(reference);

        s.Reset();
        var calls = new List<int>();
        var vault = new RandomVault(
            x =>
            {
                calls.Add(x.Length);
                s.NextBytes(x);
            },
            int.MaxValue);
        vault.BufferSize.Is(4096);

        // 10,000 bytes exceed the capped threshold (4096), so the request goes straight to the generator.
        var output = new byte[10_000];
        vault.NextBytes(output);
        output.AsSpan().SequenceEqual(reference.AsSpan(0, 10_000)).IsTrue();
        calls.Is(10_000);

        // A request of exactly BufferSize bytes is served from a refilled buffer.
        output = new byte[4096];
        vault.NextBytes(output);
        output.AsSpan().SequenceEqual(reference.AsSpan(10_000, 4096)).IsTrue();
        calls.Is(10_000, 4096);

        // One byte more than BufferSize bypasses the (now empty) buffer.
        output = new byte[4097];
        vault.NextBytes(output);
        output.AsSpan().SequenceEqual(reference.AsSpan(14_096, 4097)).IsTrue();
        calls.Is(10_000, 4096, 4097);
    }

    [Fact]
    public void ZeroThresholdSendsUnbufferedRemaindersToGenerator()
    {
        var reference = new byte[8192];
        var s = new SerialNumberGenerator();
        s.NextBytes(reference);

        s.Reset();
        var calls = new List<int>();
        var vault = new RandomVault(
            x =>
            {
                calls.Add(x.Length);
                s.NextBytes(x);
            },
            0);

        var one = new byte[1];
        vault.NextBytes(one);
        one[0].Is(reference[0]);
        calls.Is(1);

        // NextUInt64 always uses the buffer and continues the generator's stream from byte 1.
        vault.NextUInt64().Is(MemoryMarshal.Read<ulong>(reference.AsSpan(1)));
        calls.Is(1, 4096);

        // Buffered bytes are used first; only the rest goes to the generator.
        var output = new byte[4090];
        vault.NextBytes(output);
        output.AsSpan().SequenceEqual(reference.AsSpan(9, 4090)).IsTrue();
        calls.Is(1, 4096, 2);
    }

    [Fact]
    public void SharedVaultsAreUsableAndStable()
    {
        Assert.Same(RandomVault.Aegis, RandomVault.Default);
        RandomVault[] vaults = [RandomVault.Aegis, RandomVault.Xoshiro, RandomVault.SystemRng, RandomVault.Libsodium];
        vaults.Distinct().Count().Is(4);

        var instances = new RandomVault[16][];
        Parallel.For(0, instances.Length, i => instances[i] = [RandomVault.Default, RandomVault.Aegis, RandomVault.Xoshiro, RandomVault.SystemRng, RandomVault.Libsodium]);
        foreach (var x in instances)
        {
            Assert.Same(RandomVault.Aegis, x[0]);
            Assert.Same(RandomVault.Aegis, x[1]);
            Assert.Same(RandomVault.Xoshiro, x[2]);
            Assert.Same(RandomVault.SystemRng, x[3]);
            Assert.Same(RandomVault.Libsodium, x[4]);
        }

        foreach (var vault in vaults)
        {
            vault.BufferSize.Is(4096);

            var large = new byte[5000]; // Direct path
            vault.NextBytes(large);
            Assert.InRange(large.Count(x => x == 0), 0, 99); // About 20 zero bytes are expected.

            var small = new byte[17]; // Buffered path
            vault.NextBytes(small);
            small.All(x => x == 0).IsFalse();

            vault.NextUInt64().IsNot(vault.NextUInt64());
        }
    }
}
