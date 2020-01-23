// * Summary *

BenchmarkDotNet=v0.12.0, OS=Windows 10.0.18363
Intel Core i7-6700K CPU 4.00GHz (Skylake), 1 CPU, 8 logical and 4 physical cores
.NET Core SDK=3.1.100
  [Host]     : .NET Core 3.1.0 (CoreCLR 4.700.19.56402, CoreFX 4.700.19.56404), X64 RyuJIT
  DefaultJob : .NET Core 3.1.0 (CoreCLR 4.700.19.56402, CoreFX 4.700.19.56404), X64 RyuJIT


| Method     |        Mean |     Error |    StdDev |      Median |
| ---------- | ----------: | --------: | --------: | ----------: |
| FarmHash64 |    74.58 us |  1.537 us |  4.335 us |    72.84 us |
| XXHash32   |   126.38 us |  0.574 us |  0.480 us |   126.35 us |
| XXHash64   |    71.09 us |  0.478 us |  0.447 us |    70.85 us |
| SHA1       | 1,525.40 us |  8.090 us |  7.567 us | 1,521.65 us |
| SHA2_256   | 3,646.47 us |  8.449 us |  7.055 us | 3,645.70 us |
| SHA2_384   | 2,182.99 us |  6.725 us |  5.962 us | 2,179.23 us |
| SHA2_512   | 2,180.90 us |  2.545 us |  2.256 us | 2,180.61 us |
| SHA3_256   | 4,034.71 us |  7.408 us |  5.784 us | 4,035.32 us |
| SHA3_384   | 5,225.03 us |  6.537 us |  5.104 us | 5,223.53 us |
| SHA3_512   | 7,499.21 us | 12.549 us | 11.124 us | 7,497.53 us |



## HashBenchmark

BenchmarkDotNet=v0.12.0, OS=Windows 10.0.18363
Intel Core i7-6700K CPU 4.00GHz (Skylake), 1 CPU, 8 logical and 4 physical cores
.NET Core SDK=3.1.100
  [Host]     : .NET Core 3.1.0 (CoreCLR 4.700.19.56402, CoreFX 4.700.19.56404), X64 RyuJIT
  DefaultJob : .NET Core 3.1.0 (CoreCLR 4.700.19.56402, CoreFX 4.700.19.56404), X64 RyuJIT


| Method              | Length  |             Mean |         Error |        StdDev |           Median |
| ------------------- | ------- | ---------------: | ------------: | ------------: | ---------------: |
| ArcFarmHash64       | 10      |         3.507 ns |     0.0127 ns |     0.0118 ns |         3.501 ns |
| ArcFarmHash64_IHash | 10      |        53.523 ns |     1.1094 ns |     1.0896 ns |        52.676 ns |
| ArcXXHash32         | 10      |         4.732 ns |     0.0162 ns |     0.0151 ns |         4.724 ns |
| ArcXXHash32_IHash   | 10      |        21.447 ns |     0.1252 ns |     0.1171 ns |        21.381 ns |
| ArcXXHash64         | 10      |         5.591 ns |     0.0214 ns |     0.0190 ns |         5.583 ns |
| ArcXXHash64_IHash   | 10      |        24.915 ns |     0.0431 ns |     0.0382 ns |        24.908 ns |
| ArcFarmHash32       | 10      |         5.188 ns |     0.0067 ns |     0.0052 ns |         5.186 ns |
| ArcAdler32          | 10      |         8.520 ns |     0.0057 ns |     0.0051 ns |         8.519 ns |
| ArcCRC32            | 10      |        14.900 ns |     0.1020 ns |     0.0954 ns |        14.836 ns |
| ArcFarmHash64       | 100     |        15.175 ns |     0.0079 ns |     0.0062 ns |        15.174 ns |
| ArcFarmHash64_IHash | 100     |        65.133 ns |     0.7969 ns |     0.7454 ns |        65.550 ns |
| ArcXXHash32         | 100     |        17.893 ns |     0.0143 ns |     0.0120 ns |        17.895 ns |
| ArcXXHash32_IHash   | 100     |        32.791 ns |     0.7278 ns |     0.9716 ns |        32.309 ns |
| ArcXXHash64         | 100     |        15.019 ns |     0.0378 ns |     0.0353 ns |        15.002 ns |
| ArcXXHash64_IHash   | 100     |        34.104 ns |     0.0415 ns |     0.0346 ns |        34.096 ns |
| ArcFarmHash32       | 100     |        21.131 ns |     0.0074 ns |     0.0058 ns |        21.131 ns |
| ArcAdler32          | 100     |        70.220 ns |     0.1258 ns |     0.1176 ns |        70.168 ns |
| ArcCRC32            | 100     |       218.008 ns |     0.0217 ns |     0.0203 ns |       218.007 ns |
| ArcFarmHash64       | 200     |        23.382 ns |     0.1411 ns |     0.1319 ns |        23.285 ns |
| ArcFarmHash64_IHash | 200     |        74.146 ns |     1.0810 ns |     1.0112 ns |        74.731 ns |
| ArcXXHash32         | 200     |        29.174 ns |     0.0122 ns |     0.0102 ns |        29.173 ns |
| ArcXXHash32_IHash   | 200     |        42.817 ns |     0.0273 ns |     0.0214 ns |        42.818 ns |
| ArcXXHash64         | 200     |        21.357 ns |     0.1726 ns |     0.1614 ns |        21.226 ns |
| ArcXXHash64_IHash   | 200     |        41.480 ns |     0.0722 ns |     0.0676 ns |        41.460 ns |
| ArcFarmHash32       | 200     |        36.872 ns |     0.0122 ns |     0.0095 ns |        36.872 ns |
| ArcAdler32          | 200     |       132.782 ns |     0.0387 ns |     0.0323 ns |       132.781 ns |
| ArcCRC32            | 200     |       446.714 ns |     0.0776 ns |     0.0606 ns |       446.700 ns |
| ArcFarmHash64       | 1000    |        75.013 ns |     0.0684 ns |     0.0607 ns |        75.012 ns |
| ArcFarmHash64_IHash | 1000    |       141.348 ns |     2.8572 ns |     5.1520 ns |       138.142 ns |
| ArcXXHash32         | 1000    |       129.143 ns |     0.0648 ns |     0.0575 ns |       129.137 ns |
| ArcXXHash32_IHash   | 1000    |       143.105 ns |     0.0762 ns |     0.0713 ns |       143.089 ns |
| ArcXXHash64         | 1000    |        77.530 ns |     0.0415 ns |     0.0367 ns |        77.519 ns |
| ArcXXHash64_IHash   | 1000    |       103.133 ns |     0.2801 ns |     0.2620 ns |       103.187 ns |
| ArcFarmHash32       | 1000    |       164.385 ns |     0.0624 ns |     0.0487 ns |       164.384 ns |
| ArcAdler32          | 1000    |       635.627 ns |     0.4238 ns |     0.3539 ns |       635.555 ns |
| ArcCRC32            | 1000    |     2,275.086 ns |     0.3874 ns |     0.3624 ns |     2,275.044 ns |
| ArcFarmHash64       | 1000000 |    69,269.298 ns |   127.8370 ns |   119.5788 ns |    69,213.062 ns |
| ArcFarmHash64_IHash | 1000000 |   259,134.723 ns | 2,166.0873 ns | 2,026.1594 ns |   258,642.529 ns |
| ArcXXHash32         | 1000000 |   125,395.367 ns |    54.2296 ns |    45.2842 ns |   125,390.991 ns |
| ArcXXHash32_IHash   | 1000000 |   125,448.816 ns |    39.2997 ns |    34.8382 ns |   125,448.254 ns |
| ArcXXHash64         | 1000000 |    70,606.267 ns |    77.5307 ns |    68.7289 ns |    70,581.177 ns |
| ArcXXHash64_IHash   | 1000000 |    78,454.109 ns |    25.7700 ns |    21.5191 ns |    78,456.653 ns |
| ArcFarmHash32       | 1000000 |   159,185.556 ns |    77.2470 ns |    68.4775 ns |   159,166.052 ns |
| ArcAdler32          | 1000000 |   628,712.725 ns |   163.4861 ns |   136.5183 ns |   628,754.199 ns |
| ArcCRC32            | 1000000 | 2,267,448.019 ns |   423.3378 ns |   375.2780 ns | 2,267,507.617 ns |



## StringBenchmark

BenchmarkDotNet=v0.12.0, OS=Windows 10.0.18363
Intel Core i7-6700K CPU 4.00GHz (Skylake), 1 CPU, 8 logical and 4 physical cores
.NET Core SDK=3.1.100
  [Host]     : .NET Core 3.1.0 (CoreCLR 4.700.19.56402, CoreFX 4.700.19.56404), X64 RyuJIT
  DefaultJob : .NET Core 3.1.0 (CoreCLR 4.700.19.56402, CoreFX 4.700.19.56404), X64 RyuJIT


| Method                 |      Mean |     Error |    StdDev |
| ---------------------- | --------: | --------: | --------: |
| String_GetHashCode     | 22.320 ns | 0.4681 ns | 0.5573 ns |
| ArcFarmHash32_Direct   | 19.019 ns | 0.1664 ns | 0.1557 ns |
| ArcFarmHash64_Direct   |  7.092 ns | 0.0379 ns | 0.0355 ns |
| ArcFarmHash64_GetBytes | 34.733 ns | 0.4058 ns | 0.3168 ns |
| ArcXXHash32_Direct     | 12.454 ns | 0.2775 ns | 0.5974 ns |
| ArcXXHash64_Direct     | 12.356 ns | 0.0674 ns | 0.0631 ns |