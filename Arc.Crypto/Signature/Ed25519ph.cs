// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// Multi-part (prehashed) Ed25519 signatures.<br/>
/// Create an instance with <see cref="New"/>, feed the message with <see cref="Update"/>,
/// then call <see cref="FinalizeAndSign"/> or <see cref="FinalizeAndVerify"/>, which reset the state for reuse.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 208)]
public ref struct Ed25519ph
{
    /// <summary>
    /// Creates and initializes a new <see cref="Ed25519ph"/> state.
    /// </summary>
    /// <returns>An initialized <see cref="Ed25519ph"/> instance.</returns>
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

    /// <summary>
    /// Appends a message fragment to the state.
    /// </summary>
    /// <param name="message">The message fragment to append.</param>
    public void Update(scoped ReadOnlySpan<byte> message)
    {
        LibsodiumInterops.crypto_sign_ed25519ph_update(ref this, message, (ulong)message.Length);
    }

    /// <summary>
    /// Signs the accumulated message and resets the state.
    /// </summary>
    /// <param name="secretKey">The secret key. The size must be <see cref="CryptoSign.SecretKeySize"/>(64 bytes).</param>
    /// <param name="signature">A span to hold the signature. The size must be <see cref="CryptoSign.SignatureSize"/>(64 bytes).</param>
    public void FinalizeAndSign(scoped ReadOnlySpan<byte> secretKey, scoped Span<byte> signature)
    {
        if (secretKey.Length != CryptoSign.SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey), CryptoSign.SecretKeySize);
        }

        if (signature.Length != CryptoSign.SignatureSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(signature), CryptoSign.SignatureSize);
        }

        LibsodiumInterops.crypto_sign_ed25519ph_final_create(ref this, signature, out var signatureLength, secretKey);
        LibsodiumInterops.crypto_sign_ed25519ph_init(ref this);
    }

    /// <summary>
    /// Verifies the signature of the accumulated message and resets the state.
    /// </summary>
    /// <param name="publicKey">The public key. The size must be <see cref="CryptoSign.PublicKeySize"/>(32 bytes).</param>
    /// <param name="signature">The signature. The size must be <see cref="CryptoSign.SignatureSize"/>(64 bytes).</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise, <see langword="false"/>.</returns>
    public bool FinalizeAndVerify(scoped ReadOnlySpan<byte> publicKey, scoped ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != CryptoSign.PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey), CryptoSign.PublicKeySize);
        }

        if (signature.Length != CryptoSign.SignatureSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(signature), CryptoSign.SignatureSize);
        }

        var verify = LibsodiumInterops.crypto_sign_ed25519ph_final_verify(ref this, signature, publicKey) == 0;
        LibsodiumInterops.crypto_sign_ed25519ph_init(ref this);
        return verify;
    }
}
