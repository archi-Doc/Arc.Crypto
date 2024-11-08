// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Blake3Test
{
    [Fact]
    public void Test1()
    {
        Span<byte> span = stackalloc byte[Blake3.Size];
        var data = new byte[1025];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i % 251);
        }

        var lengthToHash = new Dictionary<int, byte[]>();
        AddHash(0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        AddHash(1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
        AddHash(2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63");
        AddHash(3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
        AddHash(128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef");
        AddHash(1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11");
        AddHash(1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7");
        AddHash(1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444");

        foreach (var x in lengthToHash)
        {
            Blake3.Get256_Span(data.AsSpan(0, x.Key), span);
            span.SequenceEqual(x.Value.AsSpan()).IsTrue();
        }

        foreach (var x in lengthToHash)
        {
            using var hasher = Blake3Hasher.New();
            var half = x.Key / 2;
            hasher.Update(data.AsSpan(0, half));
            hasher.Update(data.AsSpan(half, x.Key - half));
            hasher.Finalize(span);
            span.SequenceEqual(x.Value.AsSpan()).IsTrue();
        }

        void AddHash(int length, string hex)
        {
            var bin = Hex.FromStringToByteArray(hex);
            bin.Length.Is(Blake3.Size);

            lengthToHash.TryAdd(length, bin);
        }
    }
}
