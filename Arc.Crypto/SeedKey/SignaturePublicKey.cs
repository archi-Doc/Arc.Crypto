// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#pragma warning disable SA1202

namespace Arc.Crypto;

[StructLayout(LayoutKind.Explicit)]
public readonly partial struct SignaturePublicKey : IValidatable, IEquatable<SignaturePublicKey>, IStringConvertible<SignaturePublicKey>
{// (s:key)
    public const char Identifier = 's';

    #region FieldAndProperty

    // [Key(0)]
    [FieldOffset(0)]
    private readonly ulong x0;

    // [Key(1)]
    [FieldOffset(8)]
    private readonly ulong x1;

    // [Key(2)]
    [FieldOffset(16)]
    private readonly ulong x2;

    // [Key(3)]
    [FieldOffset(24)]
    private readonly ulong x3;

    #endregion

    #region TypeSpecific

    public static bool TryParse(ReadOnlySpan<char> source, [MaybeNullWhen(false)] out SignaturePublicKey publicKey)
    {
        Span<byte> keyAndChecksum = stackalloc byte[SeedKeyHelper.PublicKeyAndChecksumSize];
        if (SeedKeyHelper.TryParsePublicKey(KeyOrientation.Signature, source, keyAndChecksum))
        {
            publicKey = new(keyAndChecksum);
            return true;
        }

        publicKey = default;
        return false;
    }

    public static int MaxStringLength => SeedKeyHelper.PublicKeyLengthInBase64;

    public int GetStringLength()
        => SeedKeyHelper.PublicKeyLengthInBase64;

    public bool TryFormat(Span<char> destination, out int written)
        => SeedKeyHelper.TryFormatPublicKey(this.AsSpan(), destination, out written);

    public bool TryFormatWithBracket(Span<char> destination, out int written)
        => SeedKeyHelper.TryFormatPublicKeyWithBracket(Identifier, this.AsSpan(), destination, out written);

    public SignaturePublicKey(ReadOnlySpan<byte> b)
    {
        this.x0 = BitConverter.ToUInt64(b);
        b = b.Slice(sizeof(ulong));
        this.x1 = BitConverter.ToUInt64(b);
        b = b.Slice(sizeof(ulong));
        this.x2 = BitConverter.ToUInt64(b);
        b = b.Slice(sizeof(ulong));
        this.x3 = BitConverter.ToUInt64(b);
    }

    public SignaturePublicKey(ulong x0, ulong x1, ulong x2, ulong x3)
    {
        this.x0 = x0;
        this.x1 = x1;
        this.x2 = x2;
        this.x3 = x3;
    }

    public bool Equals(SignaturePublicKey other)
        => this.x0 == other.x0 && this.x1 == other.x1 && this.x2 == other.x2 && this.x3 == other.x3;

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != SeedKeyHelper.SignatureSize)
        {
            return false;
        }

        return CryptoSign.Verify(data, this.AsSpan(), signature);
    }

    #endregion

    #region Common

    public bool IsValid
        => this.x0 != 0;

    public bool Validate()
        => this.IsValid;

    [UnscopedRef]
    public ReadOnlySpan<byte> AsSpan()
        => MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref Unsafe.AsRef(in this), 1));

    public override int GetHashCode()
        => (int)this.x0;

    public override string ToString()
    {
        Span<char> s = stackalloc char[SeedKeyHelper.PublicKeyLengthInBase64];
        this.TryFormatWithBracket(s, out _);
        return s.ToString();
    }

    #endregion
}
