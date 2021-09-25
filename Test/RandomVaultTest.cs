// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arc.Crypto;
using Xunit;

namespace Test;

public class RandomVaultTest
{
    [Fact]
    public void Test1()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(() => xo.NextULong(), x => xo.NextBytes(x));

        DoubleToString(rv.NextDouble()).Is("0.0838629710598822");
        DoubleToString(rv.NextDouble()).Is("0.3789802506626686");
        DoubleToString(rv.NextDouble()).Is("0.6800434110281394");
        DoubleToString(rv.NextDouble()).Is("0.9246929453253876");
        DoubleToString(rv.NextDouble()).Is("0.9918039142821028");

        string DoubleToString(double d) => d.ToString("F16");

        rv.NextULong().Is(14199186830065750584ul);
        rv.NextULong().Is(13267978908934200754ul);
        rv.NextULong().Is(15679888225317814407ul);
        rv.NextULong().Is(14044878350692344958ul);
        rv.NextULong().Is(10760895422300929085ul);

        // NextULong only
        xo = new Xoshiro256StarStar(42);
        rv = new RandomVault(() => xo.NextULong(), null);

        DoubleToString(rv.NextDouble()).Is("0.0838629710598822");
        DoubleToString(rv.NextDouble()).Is("0.3789802506626686");
        DoubleToString(rv.NextDouble()).Is("0.6800434110281394");
        DoubleToString(rv.NextDouble()).Is("0.9246929453253876");
        DoubleToString(rv.NextDouble()).Is("0.9918039142821028");

        rv.NextULong().Is(14199186830065750584ul);
        rv.NextULong().Is(13267978908934200754ul);
        rv.NextULong().Is(15679888225317814407ul);
        rv.NextULong().Is(14044878350692344958ul);
        rv.NextULong().Is(10760895422300929085ul);

        // NextBytes only
        xo = new Xoshiro256StarStar(42);
        rv = new RandomVault(null, x => xo.NextBytes(x));

        DoubleToString(rv.NextDouble()).Is("0.0838629710598822");
        DoubleToString(rv.NextDouble()).Is("0.3789802506626686");
        DoubleToString(rv.NextDouble()).Is("0.6800434110281394");
        DoubleToString(rv.NextDouble()).Is("0.9246929453253876");
        DoubleToString(rv.NextDouble()).Is("0.9918039142821028");

        rv.NextULong().Is(14199186830065750584ul);
        rv.NextULong().Is(13267978908934200754ul);
        rv.NextULong().Is(15679888225317814407ul);
        rv.NextULong().Is(14044878350692344958ul);
        rv.NextULong().Is(10760895422300929085ul);

        // Multi-thread
        var xo2 = new Xoshiro256StarStar(42);
        var rv2 = new RandomVault(() => xo2.NextULong(), x => xo2.NextBytes(x));

        const int P = 100;
        const int N = 1000;
        var array = new Queue<ulong>[P];
        var t = Parallel.For(0, P, x =>
        {
            var queue = new Queue<ulong>();
            for (var i = 0; i < N; i++)
            {
                queue.Enqueue(rv2.NextULong());
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
