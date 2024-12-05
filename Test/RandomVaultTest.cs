// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access
#pragma warning disable SA1649 // File name should match first type name

namespace Test;

internal class SerialNumberGenerator
{
    private byte serial;

    public SerialNumberGenerator()
    {
    }

    public void NextBytes(Span<byte> buffer)
    {
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] = this.serial++;
        }
    }

    public void Reset()
        => this.serial = 0;
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
        var vault = new RandomVault(x => s.NextBytes(x), Threshold);
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

        DoubleToString(rv.NextDouble()).Is("0.0838629710598822");
        DoubleToString(rv.NextDouble()).Is("0.3789802506626686");
        DoubleToString(rv.NextDouble()).Is("0.6800434110281394");
        DoubleToString(rv.NextDouble()).Is("0.9246929453253876");
        DoubleToString(rv.NextDouble()).Is("0.9918039142821028");

        rv.NextUInt64().Is(14199186830065750584ul);
        rv.NextUInt64().Is(13267978908934200754ul);
        rv.NextUInt64().Is(15679888225317814407ul);
        rv.NextUInt64().Is(14044878350692344958ul);
        rv.NextUInt64().Is(10760895422300929085ul);

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
}
