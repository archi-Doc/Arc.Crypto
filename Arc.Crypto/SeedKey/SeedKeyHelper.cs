// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto;

#pragma warning disable SA1204
#pragma warning disable SA1401

public static class SeedKeyHelper
{
    public const int SeedSize = 32;
    public const int PublicKeySize = 32;
    public const int PrivateKeySize = 32;
    public const int SignatureSize = 64;
    public const int ChecksumSize = 4;

    public const char PublicKeyOpenBracket = '(';
    public const char PublicKeySeparator = ':';
    public const char PublicKeyCloseBracket = ')';

    public static ReadOnlySpan<char> PrivateKeyBracket => "!!!";

    public static readonly int SeedLengthInBase64; // !!!seed!!!
    public static readonly int RawPublicKeyLengthInBase64; // key
    public static readonly int PublicKeyLengthInBase64; // (s:key)
    public static readonly int MaxPrivateKeyLengthInBase64; // !!!seed!!!(s:key)

    static SeedKeyHelper()
    {
        SeedLengthInBase64 = Base64.Url.GetEncodedLength(SeedSize + ChecksumSize) + 6; // "!!!!!!"
        RawPublicKeyLengthInBase64 = Base64.Url.GetEncodedLength(PublicKeySize + ChecksumSize); // "key"
        PublicKeyLengthInBase64 = RawPublicKeyLengthInBase64 + 4; // "(s:key)"
        MaxPrivateKeyLengthInBase64 = SeedLengthInBase64 + PublicKeyLengthInBase64; // !!!seed!!!(s:key)
    }

    public static bool TryParsePublicKey(PublicKeyOrientation orientation, ReadOnlySpan<char> source, Span<byte> key32)
    {
        if (key32.Length != PublicKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key32));
        }

        source = source.Trim();
        if (source.Length < RawPublicKeyLengthInBase64)
        {
            return false;
        }

        if (source[0] != PublicKeyOpenBracket)
        {// key
            if (source.Length != RawPublicKeyLengthInBase64)
            {
                return false;
            }

            return Base64.Url.FromStringToSpan(source, key32, out _);
        }

        if (source[^1] != PublicKeyCloseBracket)
        {
            return false;
        }

        if (source[2] == PublicKeySeparator)
        {// (s:key)
            if (IdentifierToOrientation(source[1]) != orientation)
            {
                return false;
            }

            if (source.Length != PublicKeyLengthInBase64)
            {
                return false;
            }

            return Base64.Url.FromStringToSpan(source.Slice(3, RawPublicKeyLengthInBase64), key32, out _);
        }
        else
        {// (key)
            if (source.Length != (RawPublicKeyLengthInBase64 + 2))
            {
                return false;
            }

            return Base64.Url.FromStringToSpan(source.Slice(1, RawPublicKeyLengthInBase64), key32, out _);
        }
    }

    public static PublicKeyOrientation IdentifierToOrientation(char identifier)
        => identifier switch
        {
            SignaturePublicKey.Identifier => PublicKeyOrientation.Signature,
            _ => PublicKeyOrientation.NotSpecified,
        };

    public static void SetChecksum(Span<byte> span)
    {
        if (span.Length < ChecksumSize)
        {
            throw new ArgumentOutOfRangeException();
        }

        var checksum = (uint)XxHash3.Hash64(span.Slice(0, span.Length - ChecksumSize));
        MemoryMarshal.Write(span.Slice(span.Length - ChecksumSize), checksum);
    }

    public static bool ValidateChecksum(Span<byte> span)
    {
        if (span.Length < ChecksumSize)
        {
            throw new ArgumentOutOfRangeException();
        }

        var checksum = MemoryMarshal.Read<uint>(span.Slice(span.Length - ChecksumSize));
        return checksum == (uint)XxHash3.Hash64(span.Slice(0, span.Length - ChecksumSize));
    }
}
