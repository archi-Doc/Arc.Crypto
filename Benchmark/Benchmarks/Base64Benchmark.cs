// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

#pragma warning disable SA1300 // Element should begin with upper-case letter

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Base64Benchmark
{
    private const int MaxLength = 200;
    private readonly byte[] testArray;
    private readonly byte[] testUtf8;
    private readonly string testString;

    // [Params(10, 32, MaxLength)]
    public int Length { get; set; }

    public ReadOnlySpan<byte> TestArray => this.testArray.AsSpan(0, this.Length);

    public ReadOnlySpan<byte> TestUtf8 => this.testUtf8.AsSpan(0, this.Length);

    public ReadOnlySpan<char> TestChars => this.testString.AsSpan(0, this.Length);

    public Base64Benchmark()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(() => xo.NextUInt64(), x => xo.NextBytes(x));

        this.testArray = new byte[MaxLength];
        rv.NextBytes(this.testArray);

        this.testUtf8 = Base64.Default.FromByteArrayToUtf8(this.testArray);
        this.testString = Convert.ToBase64String(this.testArray);

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

    /*[Benchmark]
    public byte[] Base64_ByteArrayToUtf8()
        => Base64.Default.FromByteArrayToUtf8(this.TestArray);

    [Benchmark]
    public byte[] gfoidl_ByteArrayToUtf8()
    {
        var length = gfoidl.Base64.Base64.Default.GetEncodedLength(this.TestArray.Length);
        Span<byte> buffer = stackalloc byte[length];
        gfoidl.Base64.Base64.Default.Encode(this.TestArray, buffer, out int consumed, out int written);
        return buffer.Slice(0, written).ToArray();
    }

    [Benchmark]
    public string Base64_ByteArrayToString()
        => Base64.Default.FromByteArrayToString(this.TestArray);

    [Benchmark]
    public string gfoidl_ToBase64String()
        => gfoidl.Base64.Base64.Default.Encode(this.TestArray);

    [Benchmark]
    public string Convert_ToBase64String()
        => Convert.ToBase64String(this.TestArray);*/

    /*[Benchmark]
    public byte[]? Base64_Utf8ToByteArray()
        => Base64.Default.FromUtf8ToByteArray(this.testUtf8);*/

    [Benchmark]
    public byte[] Base64_StringToByteArray()
        => Base64.Default.FromStringToByteArray(this.testString);

    [Benchmark]
    public byte[] gfoidl_StringToByteArray()
        => gfoidl.Base64.Base64.Default.Decode(this.testString);

    [Benchmark]
    public byte[] Convert_StringToByteArray()
        => Convert.FromBase64String(this.testString);

    [Benchmark]
    public byte[]? Base64Obsolete_StringToByteArray()
        => Benchmark.Design.Base64.FromCharsToByteArray(this.testString);
}
