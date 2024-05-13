// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Text;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1201
#pragma warning disable SA1649 // File name should match first type name

namespace Test;

public class StringConvertibleClass : IStringConvertible<StringConvertibleClass>
{// 'a'
    public StringConvertibleClass()
    {
    }

    static int IStringConvertible<StringConvertibleClass>.MaxStringLength => 1;

    static bool IStringConvertible<StringConvertibleClass>.TryParse(ReadOnlySpan<char> source, out StringConvertibleClass? instance)
    {
        if (source.Length != 1 || source[0] != 'a')
        {
            instance = null;
            return false;
        }
        else
        {
            instance = new();
            return true;
        }
    }

    int IStringConvertible<StringConvertibleClass>.GetStringLength()
    {
        throw new NotImplementedException();
    }

    bool IStringConvertible<StringConvertibleClass>.TryFormat(Span<char> destination, out int written)
    {
        if (destination.Length < 1)
        {
            written = 0;
            return false;
        }
        else
        {
            destination[0] = 'a';
            written = 1;
            return true;
        }
    }
}

public class StringConvertibleClass2 : IStringConvertible<StringConvertibleClass2>
{// string
    public StringConvertibleClass2(string data)
    {
        this.data = data;
    }

    private readonly string data;

    public static int MaxStringLength => 256;

    static bool IStringConvertible<StringConvertibleClass2>.TryParse(ReadOnlySpan<char> source, out StringConvertibleClass2? instance)
    {
        if (source.Length > MaxStringLength)
        {
            instance = null;
            return false;
        }
        else
        {
            instance = new(new string(source));
            return true;
        }
    }

    int IStringConvertible<StringConvertibleClass2>.GetStringLength()
        => this.data.Length;

    bool IStringConvertible<StringConvertibleClass2>.TryFormat(Span<char> destination, out int written)
    {
        if (destination.Length < this.data.Length)
        {
            written = 0;
            return false;
        }
        else
        {
            this.data.AsSpan().CopyTo(destination);
            written = this.data.Length;
            return true;
        }
    }
}

public class StringConvertibleTest
{
    [Fact]
    public void Test1()
    {
        var c1 = new StringConvertibleClass();
        c1.ConvertToString().Is("a");
        c1.ConvertToUtf8().Is(Encoding.UTF8.GetBytes("a"));

        var c2 = new StringConvertibleClass2("abc");
        c2.ConvertToString().Is("abc");
        c2.ConvertToUtf8().Is(Encoding.UTF8.GetBytes("abc"));
    }
}
