// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
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
    /// Gets or sets the instance of HashAlgorithm.
    /// </summary>
    public HashAlgorithm HashAlgorithm { get; protected set; }

    /// <summary>
    /// Gets empty byte[].
    /// </summary>
    public byte[] EmptyByte { get; } = new byte[] { };

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

    /// <summary>
    /// Not implemented, because HashAlgorithm does not support Span (TransformBlock()). Use <see cref="GetHash(byte[], int, int)"/> instead.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A hash.</returns>
    public byte[] GetHash(ReadOnlySpan<byte> input)
    {
        throw new NotImplementedException();
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

    /// <summary>
    /// Not implemented, because HashAlgorithm does not support Span (TransformBlock()). Use <see cref="HashUpdate(byte[], int, int)"/> instead.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    public void HashUpdate(ReadOnlySpan<byte> input)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount) => this.HashAlgorithm.TransformBlock(input, inputOffset, inputCount, null, 0);

    #region IDisposable Support
    private bool disposed = false; // To detect redundant calls.

    /// <summary>
    /// Finalizes an instance of the <see cref="HashAlgorithmWrapper"/> class.
    /// </summary>
    ~HashAlgorithmWrapper()
    {
        this.Dispose(false);
    }

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
