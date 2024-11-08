// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Arc.Crypto;

/// <summary>
/// Represents a BLAKE3 cryptographic hasher.
/// </summary>
/// <remarks>
/// This struct is used to compute BLAKE3 hashes. It must be disposed explicitly to free unmanaged resources.
/// </remarks>
public unsafe struct Blake3Hasher : IDisposable
{
    /// <summary>
    /// Construct a new Hasher for the regular hash function.
    /// </summary>
    /// <returns>A new instance of the hasher.</returns>
    /// <remarks>
    /// The struct returned needs to be disposed explicitly.
    /// </remarks>
    public static Blake3Hasher New()
    {
        return new Blake3Hasher(Blake3Interops.blake3_new());
    }

    /// <summary>
    /// Construct a new Hasher for the keyed hash function.
    /// </summary>
    /// <param name="key">A 32 byte key.</param>
    /// <returns>A new instance of the hasher.</returns>
    /// <remarks>
    /// The struct returned needs to be disposed explicitly.
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
    /// Construct a new Hasher for the key derivation function.
    /// </summary>
    /// <param name="text">The input text to derive the key from.</param>
    /// <returns>A new instance of the hasher.</returns>
    /// <remarks>
    /// The struct returned needs to be disposed explicitly.
    /// </remarks>
    public static Blake3Hasher NewDeriveKey(string text)
    {
        return NewDeriveKey(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>
    /// Construct a new Hasher for the key derivation function.
    /// </summary>
    /// <returns>A new instance of the hasher.</returns>
    /// <param name="input">The input to derive the key from.</param>
    /// <remarks>
    /// The struct returned needs to be disposed explicitly.
    /// </remarks>
    public static Blake3Hasher NewDeriveKey(ReadOnlySpan<byte> input)
    {
        fixed (void* ptr = input)
        {
            return new Blake3Hasher(Blake3Interops.blake3_new_derive_key(ptr, (void*)input.Length));
        }
    }

    #region FieldAndProperty

    private void* hasher;

    #endregion

#pragma warning disable SA1642
    /// <summary>
    /// Invalid constructor.
    /// </summary>
    [Obsolete("Use New() to create a new instance of Blake3Hasher", true)]
    public Blake3Hasher()
    {
    }
#pragma warning restore SA1642

    private Blake3Hasher(void* hasher)
    {
        this.hasher = hasher;
    }

    /// <summary>
    /// Dispose this instance.
    /// </summary>
    public void Dispose()
    {
        if (this.hasher != null)
        {
            Blake3Interops.blake3_delete(this.hasher);
        }

        this.hasher = null;
    }

    public void Reset()
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        Blake3Interops.blake3_reset(this.hasher);
    }

    /// <summary>
    /// Add input bytes to the hash state. You can call this any number of times.
    /// </summary>
    /// <param name="data">The input data byte buffer to hash.</param>
    /// <remarks>
    /// This method is always single-threaded. For multi-threading support, see <see cref="UpdateWithJoin"/> below.
    ///
    /// Note that the degree of SIMD parallelism that update can use is limited by the size of this input buffer.
    /// The 8 KiB buffer currently used by std::io::copy is enough to leverage AVX2, for example, but not enough to leverage AVX-512.
    /// A 16 KiB buffer is large enough to leverage all currently supported SIMD instruction sets.
    /// </remarks>
    public void Update(scoped ReadOnlySpan<byte> data)
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        fixed (void* ptr = data)
        {
            FastUpdate(this.hasher, ptr, data.Length);
        }
    }

    /// <summary>
    /// Add input data to the hash state. You can call this any number of times.
    /// </summary>
    /// <typeparam name="T">Type of the data.</typeparam>
    /// <param name="data">The data span to hash.</param>
    /// <remarks>
    /// This method is always single-threaded. For multi-threading support, see <see cref="UpdateWithJoin"/> below.
    ///
    /// Note that the degree of SIMD parallelism that update can use is limited by the size of this input buffer.
    /// The 8 KiB buffer currently used by std::io::copy is enough to leverage AVX2, for example, but not enough to leverage AVX-512.
    /// A 16 KiB buffer is large enough to leverage all currently supported SIMD instruction sets.
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
            FastUpdate(this.hasher, ptr, data.Length * sizeof(T));
        }
    }

    /// <summary>
    /// Add input bytes to the hash state, as with update, but potentially using multi-threading.
    /// </summary>
    /// <param name="data">The input byte buffer.</param>
    /// <remarks>
    /// To get any performance benefit from multi-threading, the input buffer size needs to be very large.
    /// As a rule of thumb on x86_64, there is no benefit to multi-threading inputs less than 128 KiB.
    /// Other platforms have different thresholds, and in general you need to benchmark your specific use case.
    /// Where possible, memory mapping an entire input file is recommended, to take maximum advantage of multi-threading without needing to tune a specific buffer size.
    /// Where memory mapping is not possible, good multi-threading performance requires doing IO on a background thread, to avoid sleeping all your worker threads while the input buffer is (serially) refilled.
    /// This is quite complicated compared to memory mapping.
    /// </remarks>
    public void UpdateWithJoin(scoped ReadOnlySpan<byte> data)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        fixed (void* ptr = data)
        {
            Blake3Interops.blake3_update_rayon(this.hasher, ptr, (void*)data.Length);
        }
    }

    /// <summary>
    /// Add input data span to the hash state, as with update, but potentially using multi-threading.
    /// </summary>
    /// <param name="data">The input data buffer.</param>
    /// <typeparam name="T">The type of the data elements.</typeparam>
    /// <remarks>
    /// To get any performance benefit from multi-threading, the input buffer size needs to be very large.
    /// As a rule of thumb on x86_64, there is no benefit to multi-threading inputs less than 128 KiB.
    /// Other platforms have different thresholds, and in general you need to benchmark your specific use case.
    /// Where possible, memory mapping an entire input file is recommended, to take maximum advantage of multi-threading without needing to tune a specific buffer size.
    /// Where memory mapping is not possible, good multi-threading performance requires doing IO on a background thread, to avoid sleeping all your worker threads while the input buffer is (serially) refilled.
    /// This is quite complicated compared to memory mapping.
    /// </remarks>
    public void UpdateWithJoin<T>(scoped ReadOnlySpan<T> data)
        where T : unmanaged
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        fixed (void* ptr = data)
        {
            void* size = (void*)(IntPtr)(data.Length * sizeof(T));
            Blake3Interops.blake3_update_rayon(this.hasher, ptr, size);
        }
    }

    /// <summary>
    /// Finalize the hash state and return the Hash of the input.
    /// </summary>
    /// <returns>The calculated 256-bit/32-byte hash.</returns>
    /// <remarks>
    /// This method is idempotent. Calling it twice will give the same result. You can also add more input and finalize again.
    /// </remarks>
    [SkipLocalsInit]
#pragma warning disable 465
    public Struct256 Finalize()
#pragma warning restore 465
    {
        var hash = default(Struct256);
        Blake3Interops.blake3_finalize(this.hasher, &hash);
        return hash;
    }

    /// <summary>
    /// Finalize the hash state to the output span, which can supply any number of output bytes.
    /// </summary>
    /// <param name="hash">The output hash, which can supply any number of output bytes.</param>
    /// <remarks>
    /// This method is idempotent. Calling it twice will give the same result. You can also add more input and finalize again.
    /// </remarks>
    public void Finalize(scoped Span<byte> hash)
    {
        if (this.hasher == null)
        {
            ThrowNullReferenceException();
        }

        ref var pData = ref MemoryMarshal.GetReference(hash);
        fixed (void* ptr = &pData)
        {
            var size = hash.Length;
            if (size == Blake3.Size)
            {
                Blake3Interops.blake3_finalize(this.hasher, ptr);
            }
            else
            {
                Blake3Interops.blake3_finalize_xof(this.hasher, ptr, (void*)(IntPtr)hash.Length);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FastUpdate(void* hasher, void* ptr, long size)
    {
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
