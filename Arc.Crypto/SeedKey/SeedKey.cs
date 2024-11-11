// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Arc.Crypto;

#pragma warning disable SA1202 // Elements should be ordered by access
#pragma warning disable SA1204
#pragma warning disable SA1401

public sealed partial class SeedKey : IEquatable<SeedKey>, IStringConvertible<SeedKey>
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
    {// !!!seed!!!, !!!seed!!!(s:key)
        Span<byte> seed = stackalloc byte[SeedKeyHelper.SeedSize];
        if (TryParseSeed(base64url, seed, out var keyOrientation))
        {
            secretKey = new(seed, keyOrientation);
            seed.Clear();
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
            CryptoHelper.ThrowSizeMismatchException(nameof(seed), SeedKeyHelper.SeedSize);
        }

        return new(seed, keyOrientation);
    }

    public static SeedKey New(SeedKey baseSeedKey, ReadOnlySpan<byte> additional)
    {
        Span<byte> hash = stackalloc byte[SeedKeyHelper.SeedSize];
        using var hasher = Blake3Hasher.New();
        hasher.Update(baseSeedKey.seed);
        hasher.Update(additional);
        hasher.Finalize(hash);

        return new(hash, baseSeedKey.KeyOrientation);
    }

    private SeedKey()
    {
    }

    private SeedKey(ReadOnlySpan<byte> seed, KeyOrientation keyOrientation)
    {
        this.seed = seed.ToArray();
        this.KeyOrientation = keyOrientation;
    }

    private static bool TryParseSeed(ReadOnlySpan<char> base64url, Span<byte> seed, out KeyOrientation keyOrientation)
    {// !!!seed!!!, !!!seed!!!(s:key)
        keyOrientation = KeyOrientation.NotSpecified;
        var span = base64url.Trim();
        if (!span.StartsWith(SeedKeyHelper.PrivateKeyBracket))
        {// Invalid
            return false;
        }

        span = span.Slice(SeedKeyHelper.PrivateKeyBracket.Length);
        var bracketPosition = span.IndexOf(SeedKeyHelper.PrivateKeyBracket);
        if (bracketPosition <= 0)
        {// Invalid
            return false;
        }

        var seedSpan = Base64.Url.FromStringToByteArray(span.Slice(0, bracketPosition)).AsSpan();
        if (seedSpan.Length != (SeedKeyHelper.SeedSize + SeedKeyHelper.ChecksumSize))
        {
            seedSpan.Clear();
            return false;
        }

        if (!SeedKeyHelper.ValidateChecksum(seedSpan))
        {
            seedSpan.Clear();
            return false;
        }

        seedSpan.Slice(0, SeedKeyHelper.SeedSize).CopyTo(seed);
        seedSpan.Clear();
        span = span.Slice(bracketPosition + SeedKeyHelper.PrivateKeyBracket.Length);
        if (span.Length == 0 || span[0] != SeedKeyHelper.PublicKeyOpenBracket)
        {
            return true;
        }

        // (i:key)
        if (span.Length < 4)
        {
            seed.Clear();
            return false;
        }

        keyOrientation = SeedKeyHelper.IdentifierToOrientation(span[1]);
        if (keyOrientation == KeyOrientation.NotSpecified)
        {// (key)
            seed.Clear();
            return false;
        }

        Span<byte> keyAndChecksum = stackalloc byte[SeedKeyHelper.PublicKeyAndChecksumSize];
        if (!SeedKeyHelper.TryParsePublicKey(keyOrientation, span, keyAndChecksum))
        {
            seed.Clear();
            return false;
        }

        var key = keyAndChecksum.Slice(0, SeedKeyHelper.PublicKeySize);
        if (keyOrientation == KeyOrientation.Encryption)
        {
            Span<byte> encryptionSecretKey = stackalloc byte[CryptoBox.SecretKeySize];
            Span<byte> encryptionPublicKey = stackalloc byte[CryptoBox.PublicKeySize];
            CryptoBox.CreateKey(seed, encryptionSecretKey, encryptionPublicKey);
            if (key.SequenceEqual(encryptionPublicKey))
            {
                return true;
            }
        }
        else if (keyOrientation == KeyOrientation.Signature)
        {
            Span<byte> signatureSecretKey = stackalloc byte[CryptoSign.SecretKeySize];
            Span<byte> signaturePublicKey = stackalloc byte[CryptoSign.PublicKeySize];
            CryptoSign.CreateKey(seed, signatureSecretKey, signaturePublicKey);
            if (key.SequenceEqual(signaturePublicKey))
            {
                return true;
            }
        }

        seed.Clear();
        return false;
    }

    #region FieldAndProperty

    // [Key(0)]
    private readonly byte[] seed = Array.Empty<byte>();

    // [Key(1)]
    public KeyOrientation KeyOrientation { get; } = KeyOrientation.NotSpecified;

    private byte[]? encryptionSecretKey; // X25519 32bytes
    private byte[]? encryptionPublicKey; // X25519 32bytes

    private byte[]? signatureSecretKey; // Ed235519 64bytes
    private byte[]? signaturePublicKey; // Ed235519 32bytes

    [MemberNotNull(nameof(encryptionSecretKey), nameof(encryptionPublicKey))]
    private void PrepareEncryptionKey()
    {
        if (this.encryptionSecretKey is null || this.encryptionPublicKey is null)
        {
            this.encryptionSecretKey = new byte[CryptoBox.SecretKeySize];
            this.encryptionPublicKey = new byte[CryptoBox.PublicKeySize];
            CryptoBox.CreateKey(this.seed, this.encryptionSecretKey, this.encryptionPublicKey);
        }
    }

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

    public EncryptionPublicKey GetEncryptionPublicKey()
    {
        this.PrepareEncryptionKey();
        return new(this.encryptionPublicKey);
    }

    public SignaturePublicKey GetSignaturePublicKey()
    {
        this.PrepareSignatureKey();
        return new(this.signaturePublicKey);
    }

    public bool TryEncrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> publicKey32, Span<byte> cipher)
    {
        if (nonce24.Length != CryptoBox.NonceSize)
        {
            return false;
        }

        if (publicKey32.Length != CryptoBox.PublicKeySize)
        {
            return false;
        }

        if (cipher.Length != message.Length + CryptoBox.MacSize)
        {
            return false;
        }

        this.PrepareEncryptionKey();
        CryptoBox.Encrypt(message, nonce24, this.encryptionSecretKey, publicKey32, cipher);
        return true;
    }

    public bool TryDecrypt(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> publicKey32, Span<byte> data)
    {
        if (nonce24.Length != CryptoBox.NonceSize)
        {
            return false;
        }

        if (publicKey32.Length != CryptoBox.PublicKeySize)
        {
            return false;
        }

        if (data.Length != cipher.Length - CryptoBox.MacSize)
        {
            return false;
        }

        return CryptoBox.TryDecrypt(cipher, nonce24, this.encryptionSecretKey, publicKey32, data);
    }

    public void Sign(ReadOnlySpan<byte> message, Span<byte> signature)
    {
        if (signature.Length != CryptoSign.SignatureSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signature), CryptoSign.SignatureSize);
        }

        this.PrepareSignatureKey();
        CryptoSign.Sign(message, this.signatureSecretKey, signature);
    }

    /*public bool Validate()
    {
        if (this.seed.Length != CryptoSign.SecretKeySize)
        {
            return false;
        }

        return true;
    }*/

    /*public override string ToString()
        => this.ToPublicKey().ToString();*/

    public bool Equals(SeedKey? other)
        => other is not null && this.seed.AsSpan().SequenceEqual(other.seed.AsSpan());

    public override int GetHashCode()
        => (int)XxHash3.Hash64(this.seed);

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
            if (this.KeyOrientation == KeyOrientation.Encryption)
            {
                var publicKey = this.GetEncryptionPublicKey();
                if (publicKey.TryFormatWithBracket(span, out w))
                {
                    written += w;
                }
            }
            else if (this.KeyOrientation == KeyOrientation.Signature)
            {
                var publicKey = this.GetSignaturePublicKey();
                if (publicKey.TryFormatWithBracket(span, out w))
                {
                    written += w;
                }
            }
        }

        return true;
    }
}
