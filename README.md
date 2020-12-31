# AtlasRhythm.Cryptography

Pure C#, portable and performant cryptography primitives.

**No security audits of this code have ever been performed. USE AT YOUR OWN RISK.**

[![Tests Status](https://img.shields.io/github/workflow/status/Atlas-Rhythm/Chacha20Poly1305.NET/Tests?label=tests&style=for-the-badge)](https://github.com/Atlas-Rhythm/Chacha20Poly1305.NET/actions?query=workflow%3ATests)

## Support

| .NET version | [Span](https://docs.microsoft.com/en-us/dotnet/api/system.span-1) support | SIMD acceleration |
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
