// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Blake3NativeLibraryTest
{
    [Fact]
    public void ProjectReferenceLoadsBundledLibrary()
    {
        // This project references Arc.Crypto as a project, so the library is only under runtimes/<rid>/native.
        var assembly = typeof(Blake3).Assembly;
        Assert.NotEqual(IntPtr.Zero, Blake3Interops.ResolveBundledLibrary(assembly, "blake3_dotnet"));
        Assert.Equal(IntPtr.Zero, Blake3Interops.ResolveBundledLibrary(assembly, "libsodium"));
        Assert.Equal(IntPtr.Zero, Blake3Interops.ResolveBundledLibrary(typeof(Blake3NativeLibraryTest).Assembly, "blake3_dotnet"));
    }

    [Fact]
    public void PortableRuntimeIdentifier()
    {
        var runtimeIdentifier = RuntimeInformation.RuntimeIdentifier;
        if (!runtimeIdentifier.Contains('.'))
        {// Official runtimes already report a portable RID.
            Assert.Equal(runtimeIdentifier, Blake3Interops.GetPortableRuntimeIdentifier(runtimeIdentifier));
        }

        if (OperatingSystem.IsLinux())
        {
            var architecture = Blake3Interops.GetPortableRuntimeIdentifier("linux")!.Split('-')[^1];
            Assert.Equal($"linux-{architecture}", Blake3Interops.GetPortableRuntimeIdentifier($"ubuntu.24.04-{architecture}"));
            Assert.Equal($"linux-musl-{architecture}", Blake3Interops.GetPortableRuntimeIdentifier($"alpine.3.21-{architecture}"));
        }
    }
}
