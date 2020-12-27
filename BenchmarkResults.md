```ini

BenchmarkDotNet=v0.12.1, OS=Windows 10.0.17763.1637 (1809/October2018Update/Redstone5)
Intel Core i7-7700HQ CPU 2.80GHz (Kaby Lake), 1 CPU, 8 logical and 4 physical cores
.NET Core SDK=5.0.100
  [Host]     : .NET Core 5.0.0 (CoreCLR 5.0.20.51904, CoreFX 5.0.20.51904), X64 RyuJIT
  DefaultJob : .NET Core 5.0.0 (CoreCLR 5.0.20.51904, CoreFX 5.0.20.51904), X64 RyuJIT


```

| Method | N | Mean | Error | StdDev | Ratio | RatioSD |
| --- | --- | --: | --: | --: | --: | --: |
| **Chacha20Poly1305Roundtrip** | **1024** | **5.856 μs** | **0.0503 μs** | **0.0470 μs** | **1.00** | **0.00** |
| SodiumChacha20Poly1305Roundtrip | 1024 | 3.510 μs | 0.0362 μs | 0.0339 μs | 0.60 | 0.01 |
| AesGcmRoundtrip | 1024 | 9.341 μs | 0.0843 μs | 0.0789 μs | 1.60 | 0.02 |
|  |  |  |  |  |  |  |
| **Chacha20Poly1305Roundtrip** | **1048576** | **4,992.584 μs** | **66.4842 μs** | **62.1894 μs** | **1.00** | **0.00** |
| SodiumChacha20Poly1305Roundtrip | 1048576 | 3,007.105 μs | 28.2162 μs | 25.0129 μs | 0.60 | 0.01 |
| AesGcmRoundtrip | 1048576 | 9,263.662 μs | 139.4098 μs | 130.4041 μs | 1.86 | 0.03 |
