// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class GetStringLengthBanchmark
{
    private int number = 2525;

    public GetStringLengthBanchmark()
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
    public int StringLength()
    {
        return this.number.ToString().Length;
    }

    [Benchmark]
    public int GetStringLength()
    {// (int)Math.Floor(Math.Log10(i)) + 1;
        return Arc.BaseHelper.CountDecimalChars(this.number);
    }

    [Benchmark]
    public int MathFloor()
    {
        return (int)Math.Floor(Math.Log10(this.number)) + 1;
    }
}
