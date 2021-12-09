// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class MersenneTwisterTest
{
    [Fact]
    public void Test1()
    {
        var init = new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL };
        var mt = new MersenneTwister(init);

        // NextULong test
        mt.NextUInt64().Is(7266447313870364031UL);
        mt.NextUInt64().Is(4946485549665804864UL);
        mt.NextUInt64().Is(16945909448695747420UL);
        mt.NextUInt64().Is(16394063075524226720UL);
        mt.NextUInt64().Is(4873882236456199058UL);

        for (var i = 0; i < 990; i++)
        {
            mt.NextUInt64();
        }

        mt.NextUInt64().Is(10197035660403006684UL);
        mt.NextUInt64().Is(13004818533162292132UL);
        mt.NextUInt64().Is(9831652587047067687UL);
        mt.NextUInt64().Is(7619315254749630976UL);
        mt.NextUInt64().Is(994412663058993407UL);

        // NextDouble test
        DoubleToString(mt.NextDouble()).Is("0.35252031");
        DoubleToString(mt.NextDouble()).Is("0.51052342");
        DoubleToString(mt.NextDouble()).Is("0.79771733");
        DoubleToString(mt.NextDouble()).Is("0.39300273");
        DoubleToString(mt.NextDouble()).Is("0.27216673");

        string DoubleToString(double d) => d.ToString("F8");

        // Reset(byte[]) test
        var size = init.Length * sizeof(ulong);
        byte[] seed = new byte[size];
        Buffer.BlockCopy(init, 0, seed, 0, size);
        mt.Reset(init);

        mt.NextUInt64().Is(7266447313870364031UL);
        mt.NextUInt64().Is(4946485549665804864UL);
        mt.NextUInt64().Is(16945909448695747420UL);
        mt.NextUInt64().Is(16394063075524226720UL);
        mt.NextUInt64().Is(4873882236456199058UL);

        // NextBytes test
        var bytes = new byte[24];
        var bytes2 = new byte[24];
        var span = bytes.AsSpan();
        BitConverter.TryWriteBytes(span, 7266447313870364031UL);
        span = span.Slice(8);
        BitConverter.TryWriteBytes(span, 4946485549665804864UL);
        span = span.Slice(8);
        BitConverter.TryWriteBytes(span, 16945909448695747420UL);

        for (var i = 0; i <= 8; i++)
        {
            mt.Reset(init);
            var span2 = bytes2.AsSpan(0, 16 + i);
            mt.NextBytes(span2);
            span2.SequenceEqual(bytes.AsSpan().Slice(0, 16 + i)).IsTrue();
        }
    }
}
