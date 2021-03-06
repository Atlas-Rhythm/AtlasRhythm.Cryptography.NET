# AtlasRhythm.Cryptography

Pure C#, portable and performant cryptography primitives.

**No security audits of this code have ever been performed. USE AT YOUR OWN RISK.**

[![Tests Status](https://img.shields.io/github/workflow/status/Atlas-Rhythm/AtlasRhythm.Cryptography.NET/Tests?label=tests&style=for-the-badge)](https://github.com/Atlas-Rhythm/AtlasRhythm.Cryptography.NET/actions?query=workflow%3ATests) [![Docs](https://img.shields.io/badge/docs-master-informational?style=for-the-badge)](https://atlas-rhythm.github.io/AtlasRhythm.Cryptography.NET) [![NuGet](https://img.shields.io/nuget/v/AtlasRhythm.Cryptography?style=for-the-badge)](https://www.nuget.org/packages/AtlasRhythm.Cryptography/)

## Support

| .NET version | [Span](https://docs.microsoft.com/en-us/dotnet/api/system.span-1) | SIMD acceleration |
| :-: | :-: | :-: |
| **5.0** | ✔️ | ✔️ |
| **Core 3.1** | ✔️ | ✔️ |
| **Core 2.1** | ✔️ | ❌ |
| **Standard 2.1** | ✔️ | ❌ |
| **Standard 1.3** | ❌ | ❌ |
| **Framework 4.5** | ❌ | ❌ |
| **Framework 3.5** | ❌ | ❌ |

## AEADs

### ChaCha20-Poly1305

[![Docs](https://img.shields.io/badge/docs-master-informational?style=for-the-badge)](https://atlas-rhythm.github.io/AtlasRhythm.Cryptography.NET/api/AtlasRhythm.Cryptography.Aeads.Chacha20Poly1305.html)

-   [**ChaCha20**](#chacha20)
-   [**Poly1305**](#poly1305)
-   [Sample benchmark results](benchmark-results.md#chacha20-poly1305)

```sh
# Test
dotnet test --filter "FullyQualifiedName~Chacha20Poly1305"
# Bench
dotnet run -p AtlasRhythm.Cryptography.Benchmarks -- chacha20poly1305
```

## Ciphers

### ChaCha20

| Allocations | SSE2 | AVX2 |
| :---------: | :--: | :--: |
|      0      |  ✔️  |  ✔️  |

## MACs

### Poly1305

| Allocations | SSE2 | AVX2 |
| :---------: | :--: | :--: |
|      0      |  ❌  |  ❌  |

## License

This code is distributed under the terms of the [Apache License (Version 2.0)](LICENSE).
