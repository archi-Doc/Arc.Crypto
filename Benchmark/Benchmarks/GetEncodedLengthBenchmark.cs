// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class GetEncodedLengthBenchmark
{
    public GetEncodedLengthBenchmark()
    {
    }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public int Test1()
    {
        var x = 0;
        for (var i = 0; i < 100; i += 13)
        {
            x += Base64.Url.GetEncodedLength(i);
        }

        return x;
    }

    /*[Benchmark]
    public int Test2()
    {
        var x = 0;
        for (var i = 0; i < 100; i += 13)
        {
            x += Base64.Url.GetEncodedLength2(i);
        }

        return x;
    }

    [Benchmark]
    public int Test3()
    {
        var x = 0;
        for (var i = 0; i < 100; i += 13)
        {
            x += Base64.Url.GetEncodedLength3(i);
        }

        return x;
    }*/
}
