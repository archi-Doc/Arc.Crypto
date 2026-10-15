// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;

namespace Arc.Crypto;

/// <summary>
/// Multi-part Ed25519ph signatures (RFC 8032, SHA-512 prehash).<br/>
/// They are not compatible with <see cref="CryptoSign.Sign"/> and <see cref="CryptoSign.Verify"/>.<br/>
/// Create an instance with <see cref="New"/> (a default instance is initialized on first use), feed the message with <see cref="Update"/>,
/// then call <see cref="FinalizeAndSign"/> or <see cref="FinalizeAndVerify"/>, which reset the state for reuse.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = StateSize + 8)]
public ref struct Ed25519ph
{
    private const int StateSize = 208; // sizeof(crypto_sign_ed25519ph_state); native code uses only these bytes.

    [FieldOffset(StateSize)]
    private byte initialized; // A byte rather than a bool keeps the struct blittable for the P/Invoke calls.

    /// <summary>
    /// Creates and initializes a new <see cref="Ed25519ph"/> state.
    /// </summary>
    /// <returns>An initialized <see cref="Ed25519ph"/> instance.</returns>
    public static Ed25519ph New()
    {
        var st = default(Ed25519ph);
        st.Initialize();
        return st;
    }

#pragma warning disable SA1642
    /// <summary>
    /// Not supported; use <see cref="New"/>.
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
        this.EnsureInitialized();
        LibsodiumInterops.crypto_sign_ed25519ph_update(ref this, message, (ulong)message.Length);
    }

    /// <summary>
    /// Signs the accumulated message and resets the state.
    /// </summary>
    /// <param name="secretKey">The secret key. The size must be <see cref="CryptoSign.SecretKeySize"/>(64 bytes).</param>
    /// <param name="signature">A span to hold the signature. The size must be <see cref="CryptoSign.SignatureSize"/>(64 bytes).</param>
    /// <exception cref="ArgumentOutOfRangeException">The size of a span is invalid. The state is left unchanged.</exception>
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

        this.EnsureInitialized();
        LibsodiumInterops.crypto_sign_ed25519ph_final_create(ref this, signature, out var signatureLength, secretKey);
        LibsodiumInterops.crypto_sign_ed25519ph_init(ref this);
    }

    /// <summary>
    /// Verifies the signature of the accumulated message and resets the state.
    /// </summary>
    /// <param name="publicKey">The public key. The size must be <see cref="CryptoSign.PublicKeySize"/>(32 bytes).</param>
    /// <param name="signature">The signature. The size must be <see cref="CryptoSign.SignatureSize"/>(64 bytes).</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The size of a span is invalid. The state is left unchanged.</exception>
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

        this.EnsureInitialized();
        var verify = LibsodiumInterops.crypto_sign_ed25519ph_final_verify(ref this, signature, publicKey) == 0;
        LibsodiumInterops.crypto_sign_ed25519ph_init(ref this);
        return verify;
    }

    private void EnsureInitialized()
    {
        if (this.initialized == 0)
        {// default(Ed25519ph) has an all-zero hash state; initialize it as New() does.
            this.Initialize();
        }
    }

    private void Initialize()
    {
        LibsodiumInterops.crypto_sign_ed25519ph_init(ref this);
        this.initialized = 1;
    }
}
