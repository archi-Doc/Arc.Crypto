// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Arc.Crypto;

#pragma warning disable SA1202 // Elements should be ordered by access
#pragma warning disable SA1204
#pragma warning disable SA1401

public sealed partial class SeedKey : IValidatable, IEquatable<SeedKey>, IStringConvertible<SeedKey>
{// !!!Base64Url(Seed+Checksum)!!!(s:Base64Url(PublicKey+Checksum))
    public static int MaxStringLength => SeedKeyHelper.MaxPrivateKeyLengthInBase64;

    public int GetStringLength() => this.KeyOrientation switch
    {
        KeyOrientation.Encryption => SeedKeyHelper.MaxPrivateKeyLengthInBase64,
        KeyOrientation.Signature => SeedKeyHelper.MaxPrivateKeyLengthInBase64,
        _ => SeedKeyHelper.SeedLengthInBase64,
    };

    public bool TryFormat(Span<char> destination, out int written)
        => this.UnsafeTryFormat(destination, out written);

    public static bool TryParse(ReadOnlySpan<char> base64url, [MaybeNullWhen(false)] out SeedKey secretKey)
    {// !!!seed!!!, !!!seed!!!(key), !!!seed!!!(s:key)
        Span<byte> seed = stackalloc byte[SeedKeyHelper.SeedSize];
        if (TryParseKey(base64url, seed, out var keyOrientation))
        {
            secretKey = new(seed, keyOrientation);
            return true;
        }
        else
        {
            secretKey = default;
            return false;
        }
    }

    public static SeedKey New(KeyOrientation keyOrientation)
    {
        Span<byte> seed = stackalloc byte[SeedKeyHelper.SeedSize];
        CryptoRandom.NextBytes(seed);
        return new(seed, keyOrientation);
    }

    public static SeedKey New(ReadOnlySpan<byte> seed, KeyOrientation keyOrientation)
    {
        if (seed.Length != SeedKeyHelper.SeedSize)
        {
            throw new ArgumentOutOfRangeException(nameof(seed));
        }

        return new(seed, keyOrientation);
    }

    private SeedKey()
    {
    }

    private SeedKey(ReadOnlySpan<byte> seed, KeyOrientation keyOrientation)
    {
        this.seed = seed.ToArray();
        this.KeyOrientation = keyOrientation;
    }

    private static bool TryParseKey(ReadOnlySpan<char> base64url, Span<byte> seed, out KeyOrientation keyOrientation)
    {// !!!seed!!!, !!!seed!!!(key), !!!seed!!!(s:key)
        keyOrientation = KeyOrientation.NotSpecified;
        ReadOnlySpan<char> span = base64url.Trim();
        if (!span.StartsWith(SeedKeyHelper.PrivateKeyBracket))
        {// !!!abc
            return false;
        }
        //
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

        privateBytes.AsSpan().Slice(0, privateBytes.Length - SeedKeyHelper.ChecksumSize).CopyTo(seed);
        return true;
    }

    #region FieldAndProperty

    // [Key(0)]
    private readonly byte[] seed = Array.Empty<byte>();

    public KeyOrientation KeyOrientation { get; } = KeyOrientation.NotSpecified;

    private byte[]? signatureSecretKey; // Ed235519 64bytes
    private byte[]? signaturePublicKey; // Ed235519 32bytes

    /*private byte[] SignaturePublicKey
    {
        get
        {
            if (this.signaturePublicKey is null)
            {
                this.signatureSecretKey = new byte[CryptoSign.SecretKeySize];
                this.signaturePublicKey = new byte[CryptoSign.PublicKeySize];
                CryptoSign.CreateKey(this.seed, this.signatureSecretKey, this.signaturePublicKey);
            }

            return this.signaturePublicKey;
        }
    }*/

    [MemberNotNull(nameof(signatureSecretKey), nameof(signaturePublicKey))]
    private void PrepareSignatureKey()
    {
        if (this.signatureSecretKey is null || this.signaturePublicKey is null)
        {
            this.signatureSecretKey = new byte[CryptoSign.SecretKeySize];
            this.signaturePublicKey = new byte[CryptoSign.PublicKeySize];
            CryptoSign.CreateKey(this.seed, this.signatureSecretKey, this.signaturePublicKey);
        }
    }

    #endregion

    public SignaturePublicKey GetSignaturePublicKey()
    {
        this.PrepareSignatureKey();
        return new(this.signaturePublicKey);
    }

    public void Sign(ReadOnlySpan<byte> message, Span<byte> signature)
    {
        if (signature.Length != CryptoSign.SignatureSize)
        {
            throw new ArgumentOutOfRangeException(nameof(signature));
        }

        this.PrepareSignatureKey();
        CryptoSign.Sign(message, this.signatureSecretKey, signature);
    }

    public bool TryWritePublicKey(Span<byte> publicKey, out int written)
    {
        if (publicKey.Length < CryptoSign.PublicKeySize)
        {
            written = 0;
            return false;
        }

        CryptoSign.SecretKeyToPublicKey(this.seed, publicKey);
        written = CryptoSign.PublicKeySize;
        return true;
    }

    public bool Validate()
    {
        if (this.seed.Length != CryptoSign.SecretKeySize)
        {
            return false;
        }

        return true;
    }

    public bool Equals(SeedKey? other)
        => other is not null && this.seed.AsSpan().SequenceEqual(other.seed.AsSpan());

    public override int GetHashCode()
        => (int)XxHash3.Hash64(this.seed);

    /*public override string ToString()
        => this.ToPublicKey().ToString();*/

    public string UnsafeToString()
    {
        Span<char> span = stackalloc char[this.GetStringLength()];
        this.UnsafeTryFormat(span, out _);
        return span.ToString();
    }

    private bool UnsafeTryFormat(Span<char> destination, out int written)
    {// !!!seed!!!, !!!seed!!!(s:key)
        if (destination.Length < SeedKeyHelper.SeedLengthInBase64)
        {
            written = 0;
            return false;
        }

        Span<byte> seedSpan = stackalloc byte[SeedKeyHelper.SeedSize + SeedKeyHelper.ChecksumSize];
        this.seed.CopyTo(seedSpan);
        SeedKeyHelper.SetChecksum(seedSpan);

        Span<char> span = destination;
        SeedKeyHelper.PrivateKeyBracket.CopyTo(span);
        span = span.Slice(SeedKeyHelper.PrivateKeyBracket.Length);

        Base64.Url.FromByteArrayToSpan(seedSpan, span, out var w);
        span = span.Slice(w);

        SeedKeyHelper.PrivateKeyBracket.CopyTo(span);
        span = span.Slice(SeedKeyHelper.PrivateKeyBracket.Length);

        written = SeedKeyHelper.SeedLengthInBase64;
        if (span.Length >= SeedKeyHelper.PublicKeyLengthInBase64)
        {
            if (this.KeyOrientation == KeyOrientation.Signature)
            {
                var publicKey = this.GetSignaturePublicKey();
                publicKey.TryFormatWithBracket(span, out w);
                written += w;
            }
        }

        return true;
    }
}
