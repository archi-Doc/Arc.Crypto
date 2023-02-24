// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using Xunit;

namespace Test;

public class Xoshiro256StarStarTest
{
    [Fact]
    public void Test1()
    {
        // SplitMix64
        var seed = 1234567ul;
        Xoshiro256StarStar.SplitMix64(ref seed).Is(6457827717110365317ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(3203168211198807973ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(9817491932198370423ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(4593380528125082431ul);
        Xoshiro256StarStar.SplitMix64(ref seed).Is(16408922859458223821ul);

        var xo = new Xoshiro256StarStar(42);
        DoubleToString(xo.NextDouble()).Is("0.0838629710598822");
        DoubleToString(xo.NextDouble()).Is("0.3789802506626686");
        DoubleToString(xo.NextDouble()).Is("0.6800434110281394");
        DoubleToString(xo.NextDouble()).Is("0.9246929453253876");
        DoubleToString(xo.NextDouble()).Is("0.9918039142821028");

        string DoubleToString(double d) => d.ToString("F16");

        xo.NextUInt64().Is(14199186830065750584ul);
        xo.NextUInt64().Is(13267978908934200754ul);
        xo.NextUInt64().Is(15679888225317814407ul);
        xo.NextUInt64().Is(14044878350692344958ul);
        xo.NextUInt64().Is(10760895422300929085ul);
    }
}
