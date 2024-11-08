// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Arc.Crypto;

#pragma warning disable SA1300 // Element should begin with upper-case letter

internal static unsafe partial class Blake3Interops
{
    private const string Name = "blake3_dotnet";

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void* blake3_new();

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void* blake3_new_keyed(void* ptr32Bytes);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void* blake3_new_derive_key(void* ptr, void* size);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void blake3_hash(void* ptr, void* size, void* ptrOut);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl, EntryPoint = "blake3_hash")]
    public static extern void blake3_hash_preemptive(void* ptr, void* size, void* ptrOut);

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
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

    [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
    [SuppressGCTransition]
    public static extern void blake3_finalize_seek_xof(void* hasher, ulong offset, void* ptr, void* size);
}
