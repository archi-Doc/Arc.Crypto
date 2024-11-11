// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;

namespace Arc.Crypto;

[StructLayout(LayoutKind.Explicit, Size = 208)]
public ref struct Ed25519ph
{
    public static Ed25519ph New()
    {
        var st = default(Ed25519ph);
        LibsodiumInterops.crypto_sign_ed25519ph_init(ref st);
        return st;
    }

#pragma warning disable SA1642
    /// <summary>
    /// Invalid constructor.
    /// </summary>
    [Obsolete("Use New() to create a new instance of Ed25519ph", true)]
    public Ed25519ph()
    {
    }
#pragma warning restore SA1642

    public void Update(scoped ReadOnlySpan<byte> message)
    {
        var n = LibsodiumInterops.crypto_sign_ed25519ph_update(ref this, message, (ulong)message.Length);
    }

    public void FinalizeAndSign(scoped ReadOnlySpan<byte> secretKey, scoped Span<byte> signature)
    {
        if (secretKey.Length != CryptoSign.SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), CryptoSign.SecretKeySize);
        }

        if (signature.Length != CryptoSign.SignatureSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signature), CryptoSign.SignatureSize);
        }

        LibsodiumInterops.crypto_sign_ed25519ph_final_create(ref this, signature, out var signatureLength, secretKey);
        LibsodiumInterops.crypto_sign_ed25519ph_init(ref this);
    }

    public bool FinalizeAndVerify(scoped ReadOnlySpan<byte> publicKey, scoped ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != CryptoSign.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), CryptoSign.PublicKeySize);
        }

        if (signature.Length != CryptoSign.SignatureSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signature), CryptoSign.SignatureSize);
        }

        var verify = LibsodiumInterops.crypto_sign_ed25519ph_final_verify(ref this, signature, publicKey) == 0;
        LibsodiumInterops.crypto_sign_ed25519ph_init(ref this);
        return verify;
    }
}
