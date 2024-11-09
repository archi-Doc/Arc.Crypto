// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

#pragma warning disable SA1204
#pragma warning disable SA1401

public interface IValidatable
{
    /// <summary>
    /// Validate that object members are appropriate.
    /// </summary>
    /// <returns><see langword="true" />: Success.</returns>
    bool Validate();
}
