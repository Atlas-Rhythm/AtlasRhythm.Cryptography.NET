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
| **Chacha20Poly1305Roundtrip** | **.NET Core 5.0** | **.NET Core 5.0** | **1024** | **7.454 μs** | **0.0729 μs** | **0.0646 μs** | **1.00** | **0.00** |
| SodiumChacha20Poly1305Roundtrip | .NET Core 5.0 | .NET Core 5.0 | 1024 | 3.508 μs | 0.0203 μs | 0.0190 μs | 0.47 | 0.00 |
| AesGcmRoundtrip | .NET Core 5.0 | .NET Core 5.0 | 1024 | 9.340 μs | 0.1193 μs | 0.1058 μs | 1.25 | 0.02 |
| Chacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 7.109 μs | 0.0752 μs | 0.0704 μs | 0.95 | 0.01 |
| SodiumChacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 3.533 μs | 0.0497 μs | 0.0465 μs | 0.47 | 0.01 |
| AesGcmRoundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 9.343 μs | 0.0595 μs | 0.0557 μs | 1.25 | 0.02 |
|  |  |  |  |  |  |  |  |  |
| **Chacha20Poly1305Roundtrip** | **.NET Core 5.0** | **.NET Core 5.0** | **1048576** | **6,573.318 μs** | **100.3629 μs** | **93.8795 μs** | **1.00** | **0.00** |
| SodiumChacha20Poly1305Roundtrip | .NET Core 5.0 | .NET Core 5.0 | 1048576 | 3,000.906 μs | 20.6401 μs | 18.2969 μs | 0.46 | 0.01 |
| AesGcmRoundtrip | .NET Core 5.0 | .NET Core 5.0 | 1048576 | 9,144.489 μs | 114.5537 μs | 101.5489 μs | 1.39 | 0.02 |
| Chacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 6,686.611 μs | 50.5738 μs | 47.3068 μs | 1.02 | 0.02 |
| SodiumChacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 3,058.571 μs | 36.6213 μs | 32.4638 μs | 0.46 | 0.01 |
| AesGcmRoundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 9,085.720 μs | 45.7453 μs | 35.7149 μs | 1.38 | 0.02 |
