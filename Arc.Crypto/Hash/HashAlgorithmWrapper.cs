// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Security.Cryptography;

#pragma warning disable SA1124 // Do not use regions
#pragma warning disable SA1201 // Elements should appear in the correct order
#pragma warning disable SA1402 // File may only contain a single type
#pragma warning disable SA1649 // File name should match first type name

namespace Arc.Crypto;

/// <summary>
/// Wrapper class for HashAlgorithm.
/// </summary>
public abstract class HashAlgorithmWrapper : IHash, IDisposable
{
    /// <summary>
    /// The size of the buffer used to bridge the span-based API to <see cref="HashAlgorithm.TransformBlock"/>, which only accepts arrays.
    /// </summary>
    private const int TransformBufferSize = 4096;

    /// <summary>
    /// Gets or sets the instance of HashAlgorithm.
    /// </summary>
    public HashAlgorithm HashAlgorithm { get; protected set; }

    /// <summary>
    /// Gets empty byte[].
    /// </summary>
    public byte[] EmptyByte { get; } = [];

    /// <inheritdoc/>
    public virtual string HashName => "Wrapper";

    /// <inheritdoc/>
    public virtual uint HashBits => 0;

    /// <inheritdoc/>
    public virtual bool IsCryptographic => false;

    /// <summary>
    /// Initializes a new instance of the <see cref="HashAlgorithmWrapper"/> class.
    /// </summary>
    public HashAlgorithmWrapper()
    {
        this.HashAlgorithm = null!; // this.HashAlgorithm must be set in a constructor of inherited class.
    }

    /// <inheritdoc/>
    public byte[] GetHash(ReadOnlySpan<byte> input)
    {
        var hash = new byte[this.HashAlgorithm.HashSize / 8];
        if (!this.HashAlgorithm.TryComputeHash(input, hash, out var written) ||
            written != hash.Length)
        {
            throw new CryptographicException($"{this.HashName} produced an unexpected hash size.");
        }

        return hash;
    }

    /// <inheritdoc/>
    public byte[] GetHash(byte[] input, int inputOffset, int inputCount) => this.HashAlgorithm.ComputeHash(input, inputOffset, inputCount);

    /// <inheritdoc/>
    public byte[] HashFinal()
    {
        this.HashAlgorithm.TransformFinalBlock(this.EmptyByte, 0, 0);
        return this.HashAlgorithm.Hash ?? Array.Empty<byte>();
    }

    /// <inheritdoc/>
    public void HashInitialize() => this.HashAlgorithm.Initialize();

    /// <inheritdoc/>
    public void HashUpdate(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty)
        {
            return;
        }

        // TransformBlock() only accepts arrays, so feed it through a pooled buffer in bounded chunks.
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Min(input.Length, TransformBufferSize));
        try
        {
            while (!input.IsEmpty)
            {
                var size = Math.Min(input.Length, buffer.Length);
                input.Slice(0, size).CopyTo(buffer);
                this.HashAlgorithm.TransformBlock(buffer, 0, size, null, 0);
                input = input.Slice(size);
            }
        }
        finally
        {
            // Clear the buffer so the hashed material does not linger in the shared pool.
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount) => this.HashAlgorithm.TransformBlock(input, inputOffset, inputCount, null, 0);

    #region IDisposable Support
    private bool disposed = false; // To detect redundant calls.

    // No finalizer: the only resource held is the managed HashAlgorithm, whose own
    // SafeHandles are finalizable. A finalizer here would just cost every instance an
    // extra GC generation to run a Dispose(false) that has nothing to release.

    /// <inheritdoc/>
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// free managed/native resources.
    /// </summary>
    /// <param name="disposing">true: free managed resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!this.disposed)
        {
            if (disposing)
            {
                // free managed resources.
                this.HashAlgorithm.Dispose();
            }

            // free native resources here if there are any.
            this.disposed = true;
        }
    }
    #endregion
}

/// <summary>
/// SHA1 Hash Class.
/// </summary>
public class Sha1 : HashAlgorithmWrapper
{
    /// <inheritdoc/>
    public override string HashName => "SHA1";

    /// <inheritdoc/>
    public override uint HashBits => 160;

    /// <inheritdoc/>
    public override bool IsCryptographic => true;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sha1"/> class.
    /// </summary>
    public Sha1()
    {
        this.HashAlgorithm = System.Security.Cryptography.SHA1.Create();
    }
}

/// <summary>
/// SHA2-256 Hash Class.
/// </summary>
public class Sha2_256 : HashAlgorithmWrapper
{
    /// <inheritdoc/>
    public override string HashName => "SHA2-256";

    /// <inheritdoc/>
    public override uint HashBits => 256;

    /// <inheritdoc/>
    public override bool IsCryptographic => true;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sha2_256"/> class.
    /// </summary>
    public Sha2_256()
    {
        this.HashAlgorithm = System.Security.Cryptography.SHA256.Create();
    }
}

/// <summary>
/// SHA2-386 Hash Class.
/// </summary>
public class Sha2_384 : HashAlgorithmWrapper
{
    /// <inheritdoc/>
    public override string HashName => "SHA2-384";

    /// <inheritdoc/>
    public override uint HashBits => 384;

    /// <inheritdoc/>
    public override bool IsCryptographic => true;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sha2_384"/> class.
    /// </summary>
    public Sha2_384()
    {
        this.HashAlgorithm = System.Security.Cryptography.SHA384.Create();
    }
}

/// <summary>
/// SHA2-512 Hash Class.
/// </summary>
public class Sha2_512 : HashAlgorithmWrapper
{
    /// <inheritdoc/>
    public override string HashName => "SHA2-512";

    /// <inheritdoc/>
    public override uint HashBits => 512;

    /// <inheritdoc/>
    public override bool IsCryptographic => true;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sha2_512"/> class.
    /// </summary>
    public Sha2_512()
    {
        this.HashAlgorithm = System.Security.Cryptography.SHA512.Create();
    }
}
