// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Collections;
using System.Collections.Concurrent;
using Arc.Collections;
using Arc.Crypto;
using Arc.Threading;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Utf16HashtableBenchmark
{
    private const string Id = "fghjkl1234567890";
    private readonly Lock lockObject = new Lock();
    private readonly Dictionary<string, string> dictionary;
    // private readonly Dictionary<char[], string> dictionary2;
    private readonly Dictionary<string, string>.AlternateLookup<ReadOnlySpan<char>> lookup;
    // private readonly Dictionary<char[], string>.AlternateLookup<ReadOnlySpan<char>> lookup2;
    private readonly Utf16Hashtable<string> utf16Hashtable;
    private readonly ConcurrentDictionary<string, string> concurrentDictionary = new();
    private readonly Hashtable hashtable = new();
    private readonly UnorderedMap<string, string> unorderedMap = new();
    private readonly UnorderedMapSlim<string, string> unorderedMapSlim = new();
    private readonly Utf16UnorderedMap<string> utf16UnorderedMap = new();

    public Utf16HashtableBenchmark()
    {
        string[] strings = [
            "a",
            "bbb",
            "0a123456",
            $"{Id}a",
            string.Empty,
            "qwertyuiioo",
            "987654321987654321",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "123456789",
            "0a1234560a123456",
            "xyz555555xyz555555xyz555555",
            Id,
            "qwertyuiqwertyuiqwertyui",
            $"{Id} ",
            $"{Id}0",
            "abcd",];

        this.dictionary = new();
        // this.dictionary2 = new(Utf16StringEqualityComparer.Default);
        this.lookup = this.dictionary.GetAlternateLookup<ReadOnlySpan<char>>();
        // this.lookup2 = this.dictionary2.GetAlternateLookup<ReadOnlySpan<char>>();
        this.utf16Hashtable = new();
        this.concurrentDictionary = new();
        for (var i = 0; i < strings.Length; i++)
        {
            this.dictionary.Add(strings[i], strings[i]);
            // this.lookup2.TryAdd(strings[i].AsSpan(), strings[i]);
            this.utf16Hashtable.TryAdd(strings[i], strings[i]);
            this.concurrentDictionary.TryAdd(strings[i], strings[i]);
            this.hashtable.Add(strings[i], strings[i]);
            this.unorderedMap.Add(strings[i], strings[i]);
            this.unorderedMapSlim.Add(strings[i], strings[i]);
            this.utf16UnorderedMap.Add(strings[i], strings[i]);
        }
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
    public string Lookup_Dictionary()
        => this.dictionary.TryGetValue(Id, out var value) ? value : string.Empty;

    [Benchmark]
    public string Lookup_DictionaryLock()
    {
        using (this.lockObject.EnterScope())
        {
            return this.dictionary.TryGetValue(Id, out var value) ? value : string.Empty;
        }
    }

    [Benchmark]
    public string Lookup_DictionaryLookup()
    {
        using (this.lockObject.EnterScope())
        {
            return this.lookup.TryGetValue(Id.AsSpan(), out var value) ? value : string.Empty;
        }
    }

    [Benchmark]
    public string Lookup_Utf16Hashtable()
        => this.utf16Hashtable.TryGetValue(Id, out var value) ? value : string.Empty;

    [Benchmark]
    public string Lookup_ConcurrentDictionary()
        => this.concurrentDictionary.TryGetValue(Id, out var value) ? value : string.Empty;

    [Benchmark]
    public string Lookup_Hashtable()
        => this.hashtable[Id] is string st ? st : string.Empty;

    [Benchmark]
    public string Lookup_UnorderedMap()
    {
        using (this.lockObject.EnterScope())
        {
            return this.unorderedMap.TryGetValue(Id, out var value) ? value : string.Empty;
        }
    }

    [Benchmark]
    public string Lookup_UnorderedMapSlim()
    {
        using (this.lockObject.EnterScope())
        {
            return this.unorderedMapSlim.TryGetValue(Id, out var value) ? value : string.Empty;
        }
    }

    [Benchmark]
    public string Lookup_Utf16UnorderedMap()
    {
        using (this.lockObject.EnterScope())
        {
            return this.utf16UnorderedMap.TryGetValue(Id, out var value) ? value : string.Empty;
        }
    }

    [Benchmark]
    public bool RemoveAndAdd_Dictionary()
    {
        using (this.lockObject.EnterScope())
        {
            var result = this.dictionary.Remove(Id);
            this.dictionary.Add(Id, Id);
            return result;
        }
    }

    [Benchmark]
    public bool RemoveAndAdd_ConcurrentDictionary()
    {
        this.concurrentDictionary.TryRemove(Id, out _);
        return this.concurrentDictionary.TryAdd(Id, Id);
    }

    [Benchmark]
    public void RemoveAndAdd_Hashtable()
    {
        using (this.lockObject.EnterScope())
        {
            this.hashtable.Remove(Id);
            this.hashtable.Add(Id, Id);
        }
    }

    [Benchmark]
    public bool RemoveAndAdd_UnorderedMap()
    {
        using (this.lockObject.EnterScope())
        {
            var result = this.unorderedMap.Remove(Id);
            this.unorderedMap.Add(Id, Id);
            return result;
        }
    }

    [Benchmark]
    public bool RemoveAndAdd_UnorderedMapSlim()
    {
        using (this.lockObject.EnterScope())
        {
            var result = this.unorderedMapSlim.Remove(Id);
            this.unorderedMapSlim.Add(Id, Id);
            return result;
        }
    }

    [Benchmark]
    public bool RemoveAndAdd_Utf16UnorderedMap()
    {
        using (this.lockObject.EnterScope())
        {
            var result = this.utf16UnorderedMap.Remove(Id);
            this.utf16UnorderedMap.Add(Id, Id);
            return result;
        }
    }
}
