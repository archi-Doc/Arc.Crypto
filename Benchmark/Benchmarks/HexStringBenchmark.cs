// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class HexStringBenchmark
{
    private readonly string testHex = "0123456789abcdefABCDEF";
    private readonly byte[] testArray;

    public HexStringBenchmark()
    {
        this.testArray = Hex.FromStringToByteArray(this.testHex);
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
    public byte[] Ext_StringToByteArray()
        => Arc.Crypto.Obsolete.String.HexToByte(this.testHex);

    [Benchmark]
    public byte[] Hex_StringToByteArray()
        => Hex.FromStringToByteArray(this.testHex);

    [Benchmark]
    public string Hex_ByteArrayToString()
        => Hex.FromByteArrayToString(this.testArray);
}
