// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Arc.Crypto;

#pragma warning disable SA1204
#pragma warning disable SA1401

public static class KeyHelper
{
    public const int PublicKeyLength = 64;
    public const int PublicKeyHalfLength = PublicKeyLength / 2;
    public const int PrivateKeyLength = 32;
    public const int SignatureLength = 64;
    public const int EncodedLength = 1 + (sizeof(ulong) * 4);
    public const int ChecksumLength = 3;

    public static readonly int PublicKeyLengthInBase64;

    internal static ECCurve ECCurve { get; }

    static KeyHelper()
    {
        PublicKeyLengthInBase64 = Base64.Url.GetEncodedLength(EncodedLength + ChecksumLength);
    }

    public static ReadOnlySpan<char> PrivateKeyBrace => "!!!";

    public static void SetChecksum(Span<byte> span)
    {
        if (span.Length < 3)
        {
            throw new ArgumentOutOfRangeException();
        }

        var s = span.Slice(span.Length - 3);
        var checksum = XxHash3.Hash64(span.Slice(0, span.Length - 3));
        s[0] = (byte)(checksum & 0x0000_0000_0000_00FF);
        s[1] = (byte)((checksum & 0x0000_0000_00FF_0000) >> 16);
        s[2] = (byte)((checksum & 0x0000_00FF_0000_0000) >> 32);
    }

    public static bool VerifyChecksum(Span<byte> span)
    {
        if (span.Length < 3)
        {
            throw new ArgumentOutOfRangeException();
        }

        var s = span.Slice(span.Length - 3);
        var checksum = XxHash3.Hash64(span.Slice(0, span.Length - 3));
        if (s[0] != (byte)(checksum & 0x0000_0000_0000_00FF))
        {
            return false;
        }

        if (s[1] != (byte)((checksum & 0x0000_0000_00FF_0000) >> 16))
        {
            return false;
        }

        if (s[2] != (byte)((checksum & 0x0000_00FF_0000_0000) >> 32))
        {
            return false;
        }

        return true;
    }
}

public interface IValidatable
{
    /// <summary>
    /// Validate that object members are appropriate.
    /// </summary>
    /// <returns><see langword="true" />: Success.</returns>
    bool Validate();
}

public partial class Ed25519SecretKey : IValidatable, IEquatable<Ed25519SecretKey>, IStringConvertible<Ed25519SecretKey>
{// !!!Base64Url(Seed+Checksum)!!!(Base64Url(PublicKey+Checksum))
    internal const int UnsafeStringLength = 104; // 3 + Base64.Url.GetEncodedLength(Ed25519Helper.SecretKeySizeInBytes + KeyHelper.ChecksumLength) + 3 + 1 + Base64.Url.GetEncodedLength(Ed25519Helper.PublicKeySizeInBytes + KeyHelper.ChecksumLength) + 1

    public static int MaxStringLength => UnsafeStringLength;

    public int GetStringLength() => UnsafeStringLength;

    public bool TryFormat(Span<char> destination, out int written)
        => this.UnsafeTryFormat(destination, out written);

    public static bool TryParse(ReadOnlySpan<char> base64url, [MaybeNullWhen(false)] out Ed25519SecretKey secretKey)
    {
        Span<byte> key = stackalloc byte[Ed25519Helper.SecretKeySizeInBytes];
        if (TryParseKey(base64url, key))
        {
            secretKey = new(key.ToArray());
            return true;
        }
        else
        {
            secretKey = default;
            return false;
        }
    }

    public static Ed25519SecretKey New()
    {
        var secretKey = new byte[Ed25519Helper.SecretKeySizeInBytes];
        Span<byte> publicKey = stackalloc byte[Ed25519Helper.PublicKeySizeInBytes];
        Ed25519Helper.CreateKey(secretKey, publicKey);
        return new(secretKey);
    }

    public static Ed25519SecretKey New(ReadOnlySpan<byte> seed)
    {
        var secretKey = new byte[Ed25519Helper.SecretKeySizeInBytes];
        Span<byte> publicKey = stackalloc byte[Ed25519Helper.PublicKeySizeInBytes];
        Ed25519Helper.CreateKey(seed, secretKey, publicKey);
        return new(secretKey);
    }

    public Ed25519SecretKey()
    {
        var aa = 3 + Base64.Url.GetEncodedLength(Ed25519Helper.SeedSizeInBytes + KeyHelper.ChecksumLength) + 3 + 1 + Base64.Url.GetEncodedLength(Ed25519Helper.PublicKeySizeInBytes + KeyHelper.ChecksumLength) + 1;
    }

    protected Ed25519SecretKey(byte[] secretKey)
    {
        var aa = 3 + Base64.Url.GetEncodedLength(Ed25519Helper.SeedSizeInBytes + KeyHelper.ChecksumLength) + 3 + 1 + Base64.Url.GetEncodedLength(Ed25519Helper.PublicKeySizeInBytes + KeyHelper.ChecksumLength) + 1;
        if (secretKey.Length != Ed25519Helper.SecretKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        this.secretKey = secretKey;
    }

    protected static bool TryParseKey(ReadOnlySpan<char> base64url, Span<byte> secretKey)
    {//
        ReadOnlySpan<char> span = base64url.Trim();
        if (!span.StartsWith(KeyHelper.PrivateKeyBrace))
        {// !!!abc
            return false;
        }

        span = span.Slice(KeyHelper.PrivateKeyBrace.Length);
        var bracePosition = span.IndexOf(KeyHelper.PrivateKeyBrace);
        if (bracePosition <= 0)
        {// abc!!!
            return false;
        }

        var privateBytes = Base64.Url.FromStringToByteArray(span.Slice(0, bracePosition));
        if (privateBytes == null || privateBytes.Length != (KeyHelper.PrivateKeyLength + KeyHelper.ChecksumLength))
        {
            return false;
        }

        if (!KeyHelper.VerifyChecksum(privateBytes))
        {
            return false;
        }

        privateBytes.AsSpan().Slice(0, privateBytes.Length - KeyHelper.ChecksumLength).CopyTo(secretKey);
        return true;
    }

    #region FieldAndProperty

    // [Key(0)]
    protected readonly byte[] secretKey = Array.Empty<byte>();

    // protected readonly byte[] publicKey = Array.Empty<byte>();

    #endregion

    public void GetPublicKey(Span<byte> publicKey)
    {
        if (publicKey.Length != Ed25519Helper.PublicKeySizeInBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        Ed25519Helper.SecretKeyToPublicKey(this.secretKey, publicKey);
    }

    public bool TryWritePublicKey(Span<byte> publicKey, out int written)
    {
        if (publicKey.Length < Ed25519Helper.PublicKeySizeInBytes)
        {
            written = 0;
            return false;
        }

        Ed25519Helper.SecretKeyToPublicKey(this.secretKey, publicKey);
        written = Ed25519Helper.PublicKeySizeInBytes;
        return true;
    }

    public virtual bool Validate()
    {
        if (this.secretKey.Length != Ed25519Helper.SecretKeySizeInBytes)
        {
            return false;
        }

        return true;
    }

    public bool Equals(Ed25519SecretKey? other)
        => other is not null && this.secretKey.AsSpan().SequenceEqual(other.secretKey.AsSpan());

    public override int GetHashCode()
        => (int)XxHash3.Hash64(this.secretKey);

    /*public override string ToString()
        => this.ToPublicKey().ToString();*/

    public string UnsafeToString()
    {
        Span<char> span = stackalloc char[UnsafeStringLength];
        this.UnsafeTryFormat(span, out _);
        return span.ToString();
    }

    protected bool UnsafeTryFormat(Span<char> destination, out int written)
    {
        if (destination.Length < UnsafeStringLength)
        {
            written = 0;
            return false;
        }

        Span<byte> privateSpan = stackalloc byte[Ed25519Helper.SecretKeySizeInBytes + KeyHelper.ChecksumLength]; // scoped
        this.secretKey.CopyTo(privateSpan);
        KeyHelper.SetChecksum(privateSpan);

        Span<byte> publicSpan = stackalloc byte[Ed25519Helper.PublicKeySizeInBytes + KeyHelper.ChecksumLength];
        this.TryWritePublicKey(publicSpan, out _);
        KeyHelper.SetChecksum(publicSpan);

        Span<char> span = destination;
        span[0] = '!';
        span[1] = '!';
        span[2] = '!';
        span = span.Slice(3);

        Base64.Url.FromByteArrayToSpan(privateSpan, span, out var w);
        span = span.Slice(w);

        span[0] = '!';
        span[1] = '!';
        span[2] = '!';
        span[3] = '(';
        span = span.Slice(4);

        Base64.Url.FromByteArrayToSpan(publicSpan, span, out w);
        span = span.Slice(w);
        span[0] = ')';
        span = span.Slice(1);

        Debug.Assert(span.Length == 0);
        written = UnsafeStringLength;
        return true;
    }
}
