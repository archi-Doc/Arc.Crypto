// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using Arc.Collections;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class HashtableBenchmark
{
    private const int N = 100;

    private ulong[] data;
    private Dictionary<ulong, int> dictionary;
    private FrozenDictionary<ulong, int> frozenDictionary;
    private UInt64Hashtable<int> uint64Hashtable;

    public HashtableBenchmark()
    {
        var random = new Xoshiro256StarStar(1);
        this.data = new ulong[N];
        for (var i = 0; i < N; i++)
        {
            this.data[i] = random.NextUInt64();
        }

        this.dictionary = this.CreateDictionary();
        this.frozenDictionary = this.CreateFrozenDictionary();
        this.uint64Hashtable = this.CreateHashtable();
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
    public Dictionary<ulong, int> CreateDictionary()
    {
        var dictionary = new Dictionary<ulong, int>();
        for (var i = 0; i < N; i++)
        {
            dictionary.Add(this.data[i], i);
        }

        return dictionary;
    }

    [Benchmark]
    public FrozenDictionary<ulong, int> CreateFrozenDictionary()
    {
        var dictionary = new Dictionary<ulong, int>();
        for (var i = 0; i < N; i++)
        {
            dictionary.Add(this.data[i], i);
        }

        return dictionary.ToFrozenDictionary();
    }

    [Benchmark]
    public UInt64Hashtable<int> CreateHashtable()
    {
        var hashtable = new UInt64Hashtable<int>();
        for (var i = 0; i < N; i++)
        {
            hashtable.TryAdd(this.data[i], i);
        }

        return hashtable;
    }

    [Benchmark]
    public int GetDictionary()
    {
        this.dictionary.TryGetValue(this.data[N / 2], out var i);
        return i;
    }

    [Benchmark]
    public int GetFrozenDictionary()
    {
        this.frozenDictionary.TryGetValue(this.data[N / 2], out var i);
        return i;
    }

    [Benchmark]
    public int GetHashtable()
    {
        this.uint64Hashtable.TryGetValue(this.data[N / 2], out var i);
        return i;
    }
}
