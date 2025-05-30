﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Reflection;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

#pragma warning disable SA1310 // Field names should not contain underscore
#pragma warning disable CS1591
#pragma warning disable SA1402
#pragma warning disable SA1600 // Elements should be documented

namespace Benchmark;

public class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Arc.Crypto Benchmark.");

        // RandomVaultBenchmark.Test1();
        DebugRun<GetEncodedLengthBenchmark>();

        // var summary = BenchmarkRunner.Run<SpeedBenchmark>();
        var switcher = new BenchmarkSwitcher(new[]
        {
            typeof(GetEncodedLengthBenchmark),
            typeof(Utf16HashtableBenchmark),
            typeof(PasswordHashBenchmark),
            typeof(CipherBenchmark),
            typeof(Curve25519Benchmark),
            // typeof(SerializeHashBenchmark),
            typeof(Avx2Benchmark),
            typeof(DsaBenchmark),
            typeof(GetStringLengthBanchmark),
            typeof(StringHashBenchmark),
            typeof(HashtableBenchmark),
            typeof(AesBenchmark),
            typeof(StandardHashBenchmark),
            typeof(Base32ImplBenchmark),
            typeof(Base64Benchmark),
            typeof(HexStringBenchmark),
            typeof(RandomVaultBenchmark),
            typeof(CryptoRandom_NextBytes),
            typeof(CryptoRandom_NextUInt64),
            typeof(FillRandomBenchmark),
            typeof(PseudoRandomBenchmark),
            typeof(HashBenchmark),
            typeof(StringBenchmark),
            typeof(Sha256Benchmark),
            typeof(SpeedBenchmark),
        });
        switcher.Run(args);
    }

    public static void DebugRun<T>()
    where T : new()
    { // Run a benchmark in debug mode.
        var t = new T();
        var type = typeof(T);
        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance);
        var fields = type.GetFields(BindingFlags.Public | BindingFlags.Instance);
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);

        foreach (var x in fields)
        { // Set Fields.
            var attr = (ParamsAttribute[])x.GetCustomAttributes(typeof(ParamsAttribute), false);
            if (attr != null && attr.Length > 0)
            {
                if (attr[0].Values.Length > 0)
                {
                    x.SetValue(t, attr[0].Values[0]);
                }
            }
        }

        foreach (var x in properties)
        { // Set Properties.
            var attr = (ParamsAttribute[])x.GetCustomAttributes(typeof(ParamsAttribute), false);
            if (attr != null && attr.Length > 0)
            {
                if (attr[0].Values.Length > 0)
                {
                    x.SetValue(t, attr[0].Values[0]);
                }
            }
        }

        foreach (var x in methods.Where(i => i.GetCustomAttributes(typeof(GlobalSetupAttribute), false).Length > 0))
        { // [GlobalSetupAttribute]
            x.Invoke(t, null);
        }

        foreach (var x in methods.Where(i => i.GetCustomAttributes(typeof(BenchmarkAttribute), false).Length > 0))
        { // [BenchmarkAttribute]
            x.Invoke(t, null);
        }

        foreach (var x in methods.Where(i => i.GetCustomAttributes(typeof(GlobalCleanupAttribute), false).Length > 0))
        { // [GlobalCleanupAttribute]
            x.Invoke(t, null);
        }

        // obsolete code:
        // methods.Where(i => i.CustomAttributes.Select(j => j.AttributeType).Contains(typeof(GlobalSetupAttribute)))
        // bool IsNullableType(Type type) => type.IsGenericType && type.GetGenericTypeDefinition().Equals(typeof(Nullable<>));
        /* var targetType = IsNullableType(x.FieldType) ? Nullable.GetUnderlyingType(x.FieldType) : x.FieldType;
                    if (targetType != null)
                    {
                        var value = Convert.ChangeType(attr[0].Values[0], targetType);
                        x.SetValue(t, value);
                    }*/
    }
}

public class BenchmarkConfig : BenchmarkDotNet.Configs.ManualConfig
{
    public BenchmarkConfig()
    {
        this.AddExporter(BenchmarkDotNet.Exporters.MarkdownExporter.GitHub);
        this.AddDiagnoser(BenchmarkDotNet.Diagnosers.MemoryDiagnoser.Default);

        // this.AddJob(BenchmarkDotNet.Jobs.Job.ShortRun);
    }
}
