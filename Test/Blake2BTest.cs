// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Blake2BTest
{
    // Inputs on both sides of Blake3.LimitPreemptive (1024), where Blake2B switches from the SuppressGCTransition import to the normal one.
    // Input bytes are (byte)i. Expected values computed with CPython 3.12 hashlib.blake2b (digest_size=32 and the default 64).
    [Theory]
    [InlineData(1024, "f1551feeb252c7e60bb362205bd1ac2f70b145260a91d41e8c5d0a187549a5f2", "6b490f42e902f61b1ee12d3c85e34152e37c94d07ab9ea577cad6a6eb4690fad38064f53a19c225703a5c52cdc9a85add71b339d327e1630ee3432b920240e8a")]
    [InlineData(1025, "1483c7c7d406e2c43b3feb32af98d9bb401b2d67b219f07fb90d4c6fc6051853", "4ce7bad73d5ca6e76c99364489dca5be09c66e655ba2cdad3efe44530c43bebfc227166dff4f4a7d9c61e6d8193fed189ff42953295170b993bfa070c418bf27")]
    public void KnownAnswersAroundPreemptiveLimit(int length, string hash256, string hash512)
    {
        var input = new byte[length];
        for (var i = 0; i < input.Length; i++)
        {
            input[i] = (byte)i;
        }

        var expected256 = Convert.FromHexString(hash256);
        var expected512 = Convert.FromHexString(hash512);
        Blake2B.Get256ByteArray(input).Is(expected256);
        Blake2B.Get512ByteArray(input).Is(expected512);

        var value = Blake2B.Get256Struct(input);
        MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref value, 1)).ToArray().Is(expected256);

        var words = Blake2B.Get256UInt64(input);
        ReadOnlySpan<ulong> wordSpan = [words.Hash0, words.Hash1, words.Hash2, words.Hash3];
        MemoryMarshal.AsBytes(wordSpan).ToArray().Is(expected256);
    }
}
