```ini

BenchmarkDotNet=v0.12.1, OS=Windows 10.0.17763.1637 (1809/October2018Update/Redstone5)
Intel Core i7-7700HQ CPU 2.80GHz (Kaby Lake), 1 CPU, 8 logical and 4 physical cores
.NET Core SDK=5.0.100
  [Host]        : .NET Core 5.0.0 (CoreCLR 5.0.20.51904, CoreFX 5.0.20.51904), X64 RyuJIT
  .NET Core 5.0 : .NET Core 5.0.0 (CoreCLR 5.0.20.51904, CoreFX 5.0.20.51904), X64 RyuJIT
  CoreRt 5.0    : .NET 5.0.29408.02 @BuiltBy: dlab14-DDVSOWINAGE075 @Branch: master @Commit: 4ce1c21ac0d4d1a3b7f7a548214966f69ac9f199, X64 AOT


```

| Method | Job | Runtime | N | Mean | Error | StdDev | Ratio | RatioSD |
| --- | --- | --- | --- | --: | --: | --: | --: | --: |
| **Chacha20Poly1305Roundtrip** | **.NET Core 5.0** | **.NET Core 5.0** | **1024** | **9.362 μs** | **0.1641 μs** | **0.1370 μs** | **1.00** | **0.00** |
| SodiumChacha20Poly1305Roundtrip | .NET Core 5.0 | .NET Core 5.0 | 1024 | 3.505 μs | 0.0267 μs | 0.0237 μs | 0.37 | 0.01 |
| AesGcmRoundtrip | .NET Core 5.0 | .NET Core 5.0 | 1024 | 9.351 μs | 0.0634 μs | 0.0529 μs | 1.00 | 0.02 |
| Chacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 8.934 μs | 0.0667 μs | 0.0624 μs | 0.96 | 0.02 |
| SodiumChacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 3.489 μs | 0.0249 μs | 0.0233 μs | 0.37 | 0.01 |
| AesGcmRoundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 9.379 μs | 0.1120 μs | 0.1048 μs | 1.00 | 0.02 |
|  |  |  |  |  |  |  |  |  |
| **Chacha20Poly1305Roundtrip** | **.NET Core 5.0** | **.NET Core 5.0** | **1048576** | **8,421.199 μs** | **88.3591 μs** | **82.6511 μs** | **1.00** | **0.00** |
| SodiumChacha20Poly1305Roundtrip | .NET Core 5.0 | .NET Core 5.0 | 1048576 | 2,989.832 μs | 37.7254 μs | 35.2883 μs | 0.36 | 0.01 |
| AesGcmRoundtrip | .NET Core 5.0 | .NET Core 5.0 | 1048576 | 9,186.309 μs | 171.3633 μs | 168.3017 μs | 1.09 | 0.02 |
| Chacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 8,331.300 μs | 98.3834 μs | 92.0279 μs | 0.99 | 0.02 |
| SodiumChacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 3,076.049 μs | 50.0594 μs | 44.3764 μs | 0.37 | 0.01 |
| AesGcmRoundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 9,085.517 μs | 77.0106 μs | 68.2679 μs | 1.08 | 0.01 |
