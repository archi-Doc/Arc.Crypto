// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Base64Benchmark
{
    private const int MaxLength = 20;
    private readonly byte[] testArray;
    private readonly byte[] testUtf8;
    private readonly string testString;
    // private readonly byte[] testUtf8B;
    private readonly string testStringB;

    // [Params(10, 32, MaxLength)]
    [Params(MaxLength)]
    public int Length { get; set; }

    public ReadOnlySpan<byte> TestArray => this.testArray.AsSpan(0, this.Length);

    // public ReadOnlySpan<byte> TestUtf8 => this.testUtf8.AsSpan(0, this.Length);

    // public ReadOnlySpan<char> TestChars => this.testString.AsSpan(0, this.Length);

    public Base64Benchmark()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(() => xo.NextUInt64(), x => xo.NextBytes(x));

        this.testArray = new byte[MaxLength];
        rv.NextBytes(this.testArray);

        this.testUtf8 = Base64.Default.FromByteArrayToUtf8(this.testArray);
        this.testString = Convert.ToBase64String(this.testArray);
        this.testStringB = Base32Sort.Reference.FromByteArrayToString(this.testArray);

        var array = gfoidl.Base64.Base64.Default.Decode(this.testString);
    }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    // [Benchmark]
    public string Base64_ByteArrayToString()
        => Base64.Default.FromByteArrayToString(this.TestArray);

    /*[Benchmark]
    public string gfoidl_ByteArrayToString()
        => gfoidl.Base64.Base64.Default.Encode(this.TestArray);

    [Benchmark]
    public string Convert_ByteArrayToString()
        => Convert.ToBase64String(this.TestArray);*/

    // [Benchmark]
    public string Base64Obsolete_ByteArrayToString()
       => Benchmark.Design.Base64.FromByteArrayToString(this.TestArray);

    // [Benchmark]
    public string Base32Reference_ByteArrayToString()
        => Base32Sort.Reference.FromByteArrayToString(this.TestArray);

    [Benchmark]
    public string Base32Table_ByteArrayToString()
        => Base32Sort.Table.FromByteArrayToString(this.TestArray);

    // [Benchmark]
    public byte[] Base64_StringToByteArray()
        => Base64.Default.FromStringToByteArray(this.testString);

    /*[Benchmark]
    public byte[] gfoidl_StringToByteArray()
        => gfoidl.Base64.Base64.Default.Decode(this.testString);

    [Benchmark]
    public byte[] Convert_StringToByteArray()
        => Convert.FromBase64String(this.testString);*/

    // [Benchmark]
    public byte[]? Base64Obsolete_StringToByteArray()
        => Benchmark.Design.Base64.FromCharsToByteArray(this.testString);

    // [Benchmark]
    public byte[] Base32Reference_StringToByteArray()
        => Base32Sort.Reference.FromStringToByteArray(this.testStringB);

    [Benchmark]
    public byte[] Base32Table_StringToByteArray()
        => Base32Sort.Table.FromStringToByteArray(this.testStringB);
}
