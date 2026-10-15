// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Arc.Crypto;

#pragma warning disable SA1300 // Element should begin with upper-case letter

internal static unsafe partial class Blake3Interops
{
    private const string Name = "blake3_dotnet";

    static Blake3Interops()
    {
        // The CLR runs this before the first native call.
        // A project reference copies every RID to runtimes/<rid>/native, where default probing does not look.
        // NuGet deployments resolve the library before this handler is consulted.
        if (AssemblyLoadContext.GetLoadContext(typeof(Blake3Interops).Assembly) is { } context)
        {
            context.ResolvingUnmanagedDll += ResolveBundledLibrary;
        }
    }

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    public static extern void* blake3_new();

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    public static extern void* blake3_new_keyed(void* ptr32Bytes);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    public static extern void* blake3_new_derive_key(void* ptr, void* size);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void blake3_hash(void* ptr, void* size, void* ptrOut);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "blake3_hash")]
    public static extern void blake3_hash_preemptive(void* ptr, void* size, void* ptrOut);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    public static extern void blake3_delete(void* hasher);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void blake3_reset(void* hasher);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void blake3_update(void* hasher, void* ptr, void* size);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "blake3_update")]
    public static extern void blake3_update_preemptive(void* hasher, void* ptr, void* size);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    public static extern void blake3_update_rayon(void* hasher, void* ptr, void* size);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void blake3_finalize(void* hasher, void* ptr);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void blake3_finalize_xof(void* hasher, void* ptr, void* size);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "blake3_finalize_xof")]
    public static extern void blake3_finalize_xof_preemptive(void* hasher, void* ptr, void* size);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    public static extern void blake3_finalize_seek_xof(void* hasher, ulong offset, void* ptr, void* size);

    [UnconditionalSuppressMessage("SingleFile", "IL3000:Avoid accessing Assembly file path when publishing as a single file", Justification = "An empty location falls back to AppContext.BaseDirectory.")]
    internal static IntPtr ResolveBundledLibrary(Assembly assembly, string libraryName)
    {
        if (libraryName != Name || assembly != typeof(Blake3Interops).Assembly)
        {
            return IntPtr.Zero;
        }

        // Probe next to Arc.Crypto.dll, which differs from the application directory when it is loaded as a plugin dependency.
        var location = assembly.Location;
        var directory = string.IsNullOrEmpty(location) ? AppContext.BaseDirectory : Path.GetDirectoryName(location) ?? AppContext.BaseDirectory;
        var fileName = OperatingSystem.IsWindows() ? "blake3_dotnet.dll" : OperatingSystem.IsMacOS() ? "libblake3_dotnet.dylib" : "libblake3_dotnet.so";

        // Distribution-built runtimes report a distro-specific RID such as ubuntu.24.04-x64, so fall back to the portable RID.
        var runtimeIdentifier = RuntimeInformation.RuntimeIdentifier;
        var handle = TryLoad(runtimeIdentifier);
        if (handle == IntPtr.Zero && GetPortableRuntimeIdentifier(runtimeIdentifier) is { } portableRuntimeIdentifier && portableRuntimeIdentifier != runtimeIdentifier)
        {
            handle = TryLoad(portableRuntimeIdentifier);
        }

        return handle;

        IntPtr TryLoad(string rid)
            => NativeLibrary.TryLoad(Path.Combine(directory, "runtimes", rid, "native", fileName), out var loaded) ? loaded : IntPtr.Zero;
    }

    internal static string? GetPortableRuntimeIdentifier(string runtimeIdentifier)
    {
        var architecture = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.X86 => "x86",
            Architecture.Arm64 => "arm64",
            Architecture.Arm => "arm",
            _ => null,
        };

        var musl = runtimeIdentifier.Contains("musl", StringComparison.Ordinal) || runtimeIdentifier.StartsWith("alpine", StringComparison.Ordinal);
        var os = OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : OperatingSystem.IsLinux() ? (musl ? "linux-musl" : "linux") : null;
        return os is null || architecture is null ? null : $"{os}-{architecture}";
    }
}
