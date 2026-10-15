// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Unicode;

namespace Arc.Crypto;

/// <summary>
/// Represents a BLAKE3 cryptographic hasher.
/// </summary>
/// <remarks>
/// Owns unmanaged state and is not thread-safe. Dispose exactly once; never copy an initialized instance or use a copy after disposal.
/// </remarks>
public unsafe struct Blake3Hasher : IDisposable
{
    private const int ContextStackSize = 256;

    /// <summary>
    /// Encodes derivation contexts; it throws instead of replacing unpaired surrogates, so distinct contexts never collapse into one.
    /// </summary>
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// Creates a hasher for the regular hash function.
    /// </summary>
    /// <returns>A new hasher.</returns>
    /// <remarks>
    /// The returned hasher must be disposed.
    /// </remarks>
    public static Blake3Hasher New()
    {
        return new Blake3Hasher(Blake3Interops.blake3_new());
    }

    /// <summary>
    /// Creates a hasher for the keyed hash function.
    /// </summary>
    /// <param name="key">The 32-byte key.</param>
    /// <returns>A new hasher.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="key"/> is not 32 bytes long.</exception>
    /// <remarks>
    /// The returned hasher must be disposed.
    /// </remarks>
    public static Blake3Hasher NewKeyed(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentOutOfRangeException(nameof(key), "Expecting the key to be 32 bytes");
        }

        fixed (void* ptr = key)
        {
            return new Blake3Hasher(Blake3Interops.blake3_new_keyed(ptr));
        }
    }

    /// <summary>
    /// Creates a hasher for the key derivation function.
    /// </summary>
    /// <param name="context">A public, application-specific context string, encoded as UTF-8. Supply secret key material through Update.</param>
    /// <returns>A new hasher.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="context"/> contains an unpaired surrogate.</exception>
    /// <remarks>
    /// The returned hasher must be disposed.
    /// </remarks>
    public static Blake3Hasher NewDeriveKey(string context)
    {
        ArgumentNullException.ThrowIfNull(context);
        int length;
        try
        {
            length = StrictUtf8.GetByteCount(context);
        }
        catch (EncoderFallbackException ex)
        {
            throw new ArgumentException("The context must not contain unpaired surrogates.", nameof(context), ex);
        }

        byte[]? rented = null;
        Span<byte> buffer = length <= ContextStackSize ? stackalloc byte[ContextStackSize] : (rented = ArrayPool<byte>.Shared.Rent(length));
        try
        {
            var written = StrictUtf8.GetBytes(context, buffer);
            return NewDeriveKeyCore(buffer[..written]);
        }
        finally
        {
            if (rented is not null)
            {// The context is public, so the buffer is not cleared.
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Creates a hasher for the key derivation function.
    /// </summary>
    /// <param name="utf8Context">The UTF-8 encoded, public, application-specific context. Supply secret key material through Update.</param>
    /// <returns>A new hasher.</returns>
    /// <exception cref="ArgumentException"><paramref name="utf8Context"/> is not valid UTF-8.</exception>
    /// <remarks>
    /// The returned hasher must be disposed.
    /// </remarks>
    public static Blake3Hasher NewDeriveKey(ReadOnlySpan<byte> utf8Context)
    {
        if (!Utf8.IsValid(utf8Context))
        {// The native side would replace invalid sequences with U+FFFD, merging distinct contexts.
            throw new ArgumentException("The context must be valid UTF-8.", nameof(utf8Context));
        }

        return NewDeriveKeyCore(utf8Context);
    }

    #region FieldAndProperty

    private void* hasher;

    #endregion

    /// <summary>
    /// Initializes a new instance of the <see cref="Blake3Hasher"/> struct.<br/>
    /// This constructor is not supported; use <see cref="New()"/> instead.
    /// </summary>
    [Obsolete("Use New() to create a new instance of Blake3Hasher", true)]
    public Blake3Hasher()
    {
    }

    private Blake3Hasher(void* hasher)
    {
        this.hasher = hasher;
    }

    /// <summary>
    /// Releases the native hasher state. Calling it again on the same instance has no effect.
    /// </summary>
    public void Dispose()
    {
        if (this.hasher != null)
        {
            Blake3Interops.blake3_delete(this.hasher);
        }

        this.hasher = null;
    }

    /// <summary>
    /// Resets the hasher to its initial state, keeping the key or derivation context it was created with.
    /// </summary>
    /// <exception cref="NullReferenceException">The hasher is uninitialized or disposed.</exception>
    public void Reset()
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        Blake3Interops.blake3_reset(this.hasher);
    }

    /// <summary>
    /// Adds input bytes to the hash state. Can be called any number of times.
    /// </summary>
    /// <param name="data">The input bytes.</param>
    /// <exception cref="NullReferenceException">The hasher is uninitialized or disposed.</exception>
    /// <remarks>
    /// Runs on the calling thread; see <see cref="UpdateParallel(ReadOnlySpan{byte})"/> for multi-threading.<br/>
    /// SIMD parallelism is limited by the input size; 16 KiB or more per call can use every supported instruction set.
    /// </remarks>
    public void Update(scoped ReadOnlySpan<byte> data)
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        fixed (void* ptr = data)
        {
            FastUpdate(this.hasher, ptr, (nuint)data.Length);
        }
    }

    /// <summary>
    /// Adds the raw memory of <paramref name="data"/> to the hash state. Can be called any number of times.
    /// </summary>
    /// <typeparam name="T">The unmanaged element type.</typeparam>
    /// <param name="data">The input elements.</param>
    /// <exception cref="NullReferenceException">The hasher is uninitialized or disposed.</exception>
    /// <remarks>
    /// The hash depends on the native byte order and on any padding bytes in <typeparamref name="T"/>.
    /// </remarks>
    public void Update<T>(scoped ReadOnlySpan<T> data)
        where T : unmanaged
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        fixed (void* ptr = data)
        {
            FastUpdate(this.hasher, ptr, checked((nuint)data.Length * (nuint)sizeof(T)));
        }
    }

    /// <summary>
    /// Adds input bytes to the hash state like <see cref="Update(ReadOnlySpan{byte})"/>, but may use multiple threads.
    /// </summary>
    /// <param name="data">The input bytes.</param>
    /// <exception cref="NullReferenceException">The hasher is uninitialized or disposed.</exception>
    /// <remarks>
    /// Only very large inputs benefit; on x86-64 there is usually no gain below 128 KiB.
    /// </remarks>
    public void UpdateParallel(scoped ReadOnlySpan<byte> data)
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        if (data.IsEmpty)
        {
            return;
        }

        fixed (void* ptr = data)
        {
            Blake3Interops.blake3_update_rayon(this.hasher, ptr, (void*)data.Length);
        }
    }

    /// <summary>
    /// Adds the raw memory of <paramref name="data"/> to the hash state like <see cref="Update{T}(ReadOnlySpan{T})"/>, but may use multiple threads.
    /// </summary>
    /// <typeparam name="T">The unmanaged element type.</typeparam>
    /// <param name="data">The input elements.</param>
    /// <exception cref="NullReferenceException">The hasher is uninitialized or disposed.</exception>
    /// <remarks>
    /// Only very large inputs benefit; on x86-64 there is usually no gain below 128 KiB.
    /// </remarks>
    public void UpdateParallel<T>(scoped ReadOnlySpan<T> data)
        where T : unmanaged
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        if (data.IsEmpty)
        {
            return;
        }

        fixed (void* ptr = data)
        {
            void* size = (void*)checked((nuint)data.Length * (nuint)sizeof(T));
            Blake3Interops.blake3_update_rayon(this.hasher, ptr, size);
        }
    }

    /// <summary>
    /// Returns the 32-byte hash of the input so far.
    /// </summary>
    /// <returns>The 256-bit hash.</returns>
    /// <exception cref="NullReferenceException">The hasher is uninitialized or disposed.</exception>
    /// <remarks>
    /// The state is not changed: calling it again gives the same result, and more input can be added afterward.
    /// </remarks>
    [SkipLocalsInit]
    public Struct256 FinalizeHash()
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        var hash = default(Struct256);
        Blake3Interops.blake3_finalize(this.hasher, &hash);
        return hash;
    }

    /// <summary>
    /// Fills <paramref name="output"/> with the extendable output (XOF) of the input so far.
    /// </summary>
    /// <param name="output">The buffer to fill. Any length is allowed; the first 32 bytes equal <see cref="FinalizeHash()"/>, and an empty span is ignored.</param>
    /// <exception cref="NullReferenceException">The hasher is uninitialized or disposed.</exception>
    /// <remarks>
    /// The state is not changed: calling it again gives the same result, and more input can be added afterward.
    /// </remarks>
    public void FinalizeHash(scoped Span<byte> output)
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        if (output.IsEmpty)
        {
            return;
        }

        fixed (void* ptr = output)
        {
            var size = output.Length;
            if (size == Blake3.HashLength)
            {
                Blake3Interops.blake3_finalize(this.hasher, ptr);
            }
            else if (size <= Blake3.LimitPreemptive)
            {
                Blake3Interops.blake3_finalize_xof(this.hasher, ptr, (void*)(IntPtr)output.Length);
            }
            else
            {
                Blake3Interops.blake3_finalize_xof_preemptive(this.hasher, ptr, (void*)output.Length);
            }
        }
    }

    private static Blake3Hasher NewDeriveKeyCore(ReadOnlySpan<byte> utf8Context)
    {
        // Rust slices require a non-null pointer even for an empty input.
        byte empty = 0;
        fixed (void* ptr = utf8Context)
        {
            return new Blake3Hasher(Blake3Interops.blake3_new_derive_key(utf8Context.IsEmpty ? &empty : ptr, (void*)utf8Context.Length));
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FastUpdate(void* hasher, void* ptr, nuint size)
    {
        if (size == 0)
        {
            return;
        }

        if (size <= Blake3.LimitPreemptive)
        {
            Blake3Interops.blake3_update(hasher, ptr, (void*)size);
        }
        else
        {
            Blake3Interops.blake3_update_preemptive(hasher, ptr, (void*)size);
        }
    }

    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowNullReferenceException()
    {
        throw new NullReferenceException("The Hasher is not initialized or already destroyed.");
    }
}
