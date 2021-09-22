``` ini

BenchmarkDotNet=v0.13.0, OS=Windows 10.0.19043.1237 (21H1/May2021Update)
Intel Core i7-6700K CPU 4.00GHz (Skylake), 1 CPU, 8 logical and 4 physical cores
.NET SDK=6.0.100-rc.1.21463.6
  [Host]     : .NET 6.0.0 (6.0.21.45113), X64 RyuJIT
  DefaultJob : .NET 6.0.0 (6.0.21.45113), X64 RyuJIT


```
|        Method |       Mean |     Error |    StdDev | Gen 0 | Gen 1 | Gen 2 | Allocated |
|-------------- |-----------:|----------:|----------:|------:|------:|------:|----------:|
|    Random_Int |   8.613 ns | 0.0066 ns | 0.0062 ns |     - |     - |     - |         - |
|        MT_Int |   2.504 ns | 0.0046 ns | 0.0038 ns |     - |     - |     - |         - |
|      MT_ULong |   4.578 ns | 0.0190 ns | 0.0169 ns |     - |     - |     - |         - |
| Random_Double |   9.163 ns | 0.0039 ns | 0.0032 ns |     - |     - |     - |         - |
|     MT_Double |   5.490 ns | 0.0260 ns | 0.0243 ns |     - |     - |     - |         - |
|  Random_Range |  21.080 ns | 0.0764 ns | 0.0714 ns |     - |     - |     - |         - |
|      MT_Range |   6.345 ns | 0.0032 ns | 0.0025 ns |     - |     - |     - |         - |
|  Random_Bytes | 154.626 ns | 0.1338 ns | 0.1117 ns |     - |     - |     - |         - |
|      Mt_Bytes |  17.064 ns | 0.0187 ns | 0.0166 ns |     - |     - |     - |         - |
