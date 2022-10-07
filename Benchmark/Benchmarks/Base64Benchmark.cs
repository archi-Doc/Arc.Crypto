// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Globalization;
using System.Linq;
using System.Text.Unicode;
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

    [Params(10, 32, MaxLength)]
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

        var utf8 = Base64.EncodeToBase64Utf8(this.testArray);
        var utf8b = Base64b.FromByteArrayToUtf8(this.testArray);
        var eq = utf8.SequenceEqual(utf8b);

        var st = Base64.EncodeToBase64Utf16(this.testArray);
        var st2 = Base64b.FromByteArrayToString(this.testArray);
        eq = st.Equals(st2);

        this.testUtf8 = utf8;
        this.testString = Convert.ToBase64String(this.testArray);

        var array = Base64b.FromUtf8ToByteArray(utf8);
        eq = array!.SequenceEqual(this.testArray);

        st2 = gfoidl.Base64.Base64.Default.Encode(this.testArray);
        eq = st.Equals(st2);

        int length = gfoidl.Base64.Base64.Default.GetEncodedLength(this.testArray.Length);
        Span<byte> buffer = stackalloc byte[length];
        gfoidl.Base64.Base64.Default.Encode(this.testArray, buffer, out int consumed, out int written);
        utf8b = buffer.Slice(0, written).ToArray();
        eq = utf8.SequenceEqual(utf8b);
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
    public byte[] Base64_ByteArrayToUtf8()
        => Base64.EncodeToBase64Utf8(this.TestArray);

    [Benchmark]
    public byte[] Base64b_ByteArrayToUtf8()
        => Base64b.FromByteArrayToUtf8(this.TestArray);

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
        => Base64.EncodeToBase64Utf16(this.TestArray);

    [Benchmark]
    public string Base64b_ByteArrayToString()
        => Base64b.FromByteArrayToString(this.TestArray);

    [Benchmark]
    public string gfoidl_ToBase64String()
        => gfoidl.Base64.Base64.Default.Encode(this.TestArray);

    [Benchmark]
    public string Convert_ToBase64String()
        => Convert.ToBase64String(this.TestArray);

    /*[Benchmark]
    public byte[]? Base64_Utf8ToByteArray()
        => Base64.DecodeFromBase64Utf8(this.testUtf8);

    [Benchmark]
    public byte[]? Base64b_Utf8ToByteArray()
        => Base64b.FromUtf8ToByteArray(this.testUtf8);

    [Benchmark]
    public byte[]? Base64_CharsToByteArray()
        => Base64.DecodeFromBase64Utf16(this.testString);*/
}
