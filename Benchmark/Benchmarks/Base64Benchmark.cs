// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Linq;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Base64Benchmark
{
    private readonly string testHex = "0123456789abcdefABCDEF120123456789abcdefABCDEF12";
    private readonly byte[] testArray;

    public Base64Benchmark()
    {
        this.testArray = Hex.StringToByteArray(this.testHex);
        var utf8 = Base64.EncodeToBase64Utf8(this.testArray);
        var utf8b = Base64b.FromByteArrayToUtf8(this.testArray);
        var eq = utf8.SequenceEqual(utf8b);
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
        => Base64.EncodeToBase64Utf8(this.testArray);

    [Benchmark]
    public byte[] Base64b_ByteArrayToUtf8()
        => Base64b.FromByteArrayToUtf8(this.testArray);

    [Benchmark]
    public string Base64_ByteArrayToString()
        => Base64.EncodeToBase64Utf16(this.testArray);
}
