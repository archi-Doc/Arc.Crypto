// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class TemplateBenchmark
{
    public TemplateBenchmark()
    {
    }

    [Params(10)]
    public int Length { get; set; }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public byte[] Test1()
    {
        return new byte[this.Length];
    }
}
