// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Arc.Crypto;

#pragma warning disable SA1204
#pragma warning disable SA1401

public partial class SeedKey : IValidatable, IEquatable<SeedKey>, IStringConvertible<SeedKey>
{// !!!Base64Url(Seed+Checksum)!!!(s:Base64Url(PublicKey+Checksum))
    internal const int UnsafeStringLength = 104; // 3 + Base64.Url.GetEncodedLength(Ed25519Helper.SecretKeySizeInBytes + KeyHelper.ChecksumLength) + 3 + 1 + Base64.Url.GetEncodedLength(Ed25519Helper.PublicKeySizeInBytes + KeyHelper.ChecksumLength) + 1

    public static int MaxStringLength => UnsafeStringLength;

    public int GetStringLength() => UnsafeStringLength;

    public bool TryFormat(Span<char> destination, out int written)
        => this.UnsafeTryFormat(destination, out written);

    public static bool TryParse(ReadOnlySpan<char> base64url, [MaybeNullWhen(false)] out SeedKey secretKey)
    {
        Span<byte> key = stackalloc byte[CryptoSign.SecretKeySize];
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

    public static SeedKey New()
    {
        var secretKey = new byte[CryptoSign.SecretKeySize];
        Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKey(secretKey, publicKey);
        return new(secretKey);
    }

    public static SeedKey New(ReadOnlySpan<byte> seed)
    {
        var secretKey = new byte[CryptoSign.SecretKeySize];
        Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeySize];
        CryptoSign.CreateKey(seed, secretKey, publicKey);
        return new(secretKey);
    }

    public SeedKey()
    {
        var aa = 3 + Base64.Url.GetEncodedLength(CryptoSign.SeedSize + SeedKeyHelper.ChecksumSize) + 3 + 1 + Base64.Url.GetEncodedLength(CryptoSign.PublicKeySize + SeedKeyHelper.ChecksumSize) + 1;
    }

    protected SeedKey(byte[] secretKey)
    {
        var aa = 3 + Base64.Url.GetEncodedLength(CryptoSign.SeedSize + SeedKeyHelper.ChecksumSize) + 3 + 1 + Base64.Url.GetEncodedLength(CryptoSign.PublicKeySize + SeedKeyHelper.ChecksumSize) + 1;
        if (secretKey.Length != CryptoSign.SecretKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(secretKey));
        }

        this.secretKey = secretKey;
    }

    protected static bool TryParseKey(ReadOnlySpan<char> base64url, Span<byte> secretKey)
    {//
        ReadOnlySpan<char> span = base64url.Trim();
        if (!span.StartsWith(SeedKeyHelper.PrivateKeyBracket))
        {// !!!abc
            return false;
        }

        span = span.Slice(SeedKeyHelper.PrivateKeyBracket.Length);
        var bracePosition = span.IndexOf(SeedKeyHelper.PrivateKeyBracket);
        if (bracePosition <= 0)
        {// abc!!!
            return false;
        }

        var privateBytes = Base64.Url.FromStringToByteArray(span.Slice(0, bracePosition));
        if (privateBytes == null || privateBytes.Length != (SeedKeyHelper.PrivateKeySize + SeedKeyHelper.ChecksumSize))
        {
            return false;
        }

        if (!SeedKeyHelper.ValidateChecksum(privateBytes))
        {
            return false;
        }

        privateBytes.AsSpan().Slice(0, privateBytes.Length - SeedKeyHelper.ChecksumSize).CopyTo(secretKey);
        return true;
    }

    #region FieldAndProperty

    // [Key(0)]
    protected readonly byte[] secretKey = Array.Empty<byte>();

    // protected readonly byte[] publicKey = Array.Empty<byte>();

    #endregion

    public void GetPublicKey(Span<byte> publicKey)
    {
        if (publicKey.Length != CryptoSign.PublicKeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        CryptoSign.SecretKeyToPublicKey(this.secretKey, publicKey);
    }

    public bool TryWritePublicKey(Span<byte> publicKey, out int written)
    {
        if (publicKey.Length < CryptoSign.PublicKeySize)
        {
            written = 0;
            return false;
        }

        CryptoSign.SecretKeyToPublicKey(this.secretKey, publicKey);
        written = CryptoSign.PublicKeySize;
        return true;
    }

    public virtual bool Validate()
    {
        if (this.secretKey.Length != CryptoSign.SecretKeySize)
        {
            return false;
        }

        return true;
    }

    public bool Equals(SeedKey? other)
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

        Span<byte> privateSpan = stackalloc byte[CryptoSign.SecretKeySize + SeedKeyHelper.ChecksumSize]; // scoped
        this.secretKey.CopyTo(privateSpan);
        SeedKeyHelper.SetChecksum(privateSpan);

        Span<byte> publicSpan = stackalloc byte[CryptoSign.PublicKeySize + SeedKeyHelper.ChecksumSize];
        this.TryWritePublicKey(publicSpan, out _);
        SeedKeyHelper.SetChecksum(publicSpan);

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
