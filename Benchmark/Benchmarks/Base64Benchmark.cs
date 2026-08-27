// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Base64Benchmark
{
    private const int MaxLength = 200;
    private readonly byte[] testArray;
    private readonly byte[] testUtf8;
    private readonly string testString;
    // private readonly byte[] testUtf8B;
    private readonly string testStringB;
    private char[] encoded = [];
    private char[] encodedUrl = [];
    private byte[] decoded = [];

    // [Params(10, 32, MaxLength)]
    [Params(20, 200)]
    public int Length { get; set; }

    public ReadOnlySpan<byte> TestArray => this.testArray.AsSpan(0, this.Length);

    // public ReadOnlySpan<byte> TestUtf8 => this.testUtf8.AsSpan(0, this.Length);

    // public ReadOnlySpan<char> TestChars => this.testString.AsSpan(0, this.Length);

    public Base64Benchmark()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(x => xo.NextBytes(x));

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
        this.encoded = new char[Base64.Default.GetEncodedLength(this.TestArray.Length)];
        this.encodedUrl = new char[Base64.Url.GetEncodedLength(this.TestArray.Length)];
        this.decoded = new byte[this.TestArray.Length];
        Base64.Default.FromByteArrayToSpan(this.TestArray, this.encoded, out var written);
        Base64.Default.FromStringToSpan(this.encoded, this.decoded, out written);
        Debug.Assert(this.TestArray.SequenceEqual(this.decoded));

        Base64.Url.FromByteArrayToSpan(this.TestArray, this.encodedUrl, out written);
        Base64.Url.FromStringToSpan(this.encodedUrl, this.decoded, out written);
        Debug.Assert(this.TestArray.SequenceEqual(this.decoded));
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public int Base64_ByteArrayToSpan()
    {
        Base64.Default.FromByteArrayToSpan(this.TestArray, this.encoded, out var written);
        return written;
    }

    // [Benchmark]
    public int Base64_ByteArrayToSpan2()
    {
        Benchmark.Design.Base64.FromByteArrayToChars(this.TestArray, this.encoded, out var written);
        return written;
    }

    [Benchmark]
    public int Base64_ByteArrayToSpan3()
    {
        return FastBase64.Encode(this.TestArray, this.encoded);
    }

    [Benchmark]
    public int Base64_SpanToByteArray()
    {
        Base64.Default.FromStringToSpan(this.encoded, this.decoded, out var written);
        return written;
    }

    // [Benchmark]
    public int Base64_SpanToByteArray2()
    {
        Benchmark.Design.Base64.FromCharsToByteArray(this.encoded, this.decoded, out var written);
        return written;
    }

    [Benchmark]
    public int Base64_SpanToByteArray3()
    {
        return FastBase64.Decode(this.encoded, this.decoded);
    }

    [Benchmark]
    public int Base64_ByteArrayToSpanUrl()
    {
        Base64.Url.FromByteArrayToSpan(this.TestArray, this.encodedUrl, out var written);
        return written;
    }

    [Benchmark]
    public int Base64_ByteArrayToSpan3Url()
    {
        return FastBase64.Encode(this.TestArray, this.encoded);
    }

    [Benchmark]
    public int Base64_SpanToByteArrayUrl()
    {
        Base64.Url.FromStringToSpan(this.encodedUrl, this.decoded, out var written);
        return written;
    }

    [Benchmark]
    public int Base64_SpanToByteArray3Url()
    {
        return FastBase64.Decode(this.encoded, this.decoded);
    }

    /*[Benchmark]
    public string Base64_ByteArrayToString()
        => Base64.Default.FromByteArrayToString(this.TestArray);

    [Benchmark]
    public string gfoidl_ByteArrayToString()
        => gfoidl.Base64.Base64.Default.Encode(this.TestArray);

    [Benchmark]
    public string Convert_ByteArrayToString()
        => Convert.ToBase64String(this.TestArray);

    // [Benchmark]
    public string Base64Obsolete_ByteArrayToString()
       => Benchmark.Design.Base64.FromByteArrayToString(this.TestArray);*/

    /*[Benchmark]
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
        => Convert.FromBase64String(this.testString);

    // [Benchmark]
    public byte[]? Base64Obsolete_StringToByteArray()
        => Benchmark.Design.Base64.FromCharsToByteArray(this.testString);

    [Benchmark]
    public byte[] Base32Reference_StringToByteArray()
        => Base32Sort.Reference.FromStringToByteArray(this.testStringB);

    [Benchmark]
    public byte[] Base32Table_StringToByteArray()
        => Base32Sort.Table.FromStringToByteArray(this.testStringB);*/
}
