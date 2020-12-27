# Chacha20Poly1305.NET

Pure C#, performant and [RFC 8439](https://tools.ietf.org/html/rfc8439) compliant implementation of ChaCha20 and Poly1305 for Authenticated Encryption with Associated Data (AEAD).

> No security audits of this code have ever been performed. USE AT YOUR OWN RISK.

[![Tests Status](https://img.shields.io/github/workflow/status/Atlas-Rhythm/Chacha20Poly1305.NET/Tests?label=tests&style=for-the-badge)](https://github.com/Atlas-Rhythm/Chacha20Poly1305.NET/actions?query=workflow%3ATests)

ChaCha20 is stream cipher which is faster than AES in software-only implementations. Poly1305 is a fast message authentication code (MAC). They can be combined to achieve Authenticated Encryption with Associated Data (AEAD) as a fast software-only alternative to AES in Galois Counter Mode (GCM).

This library aims to be a portable, fast and correct implementation which can easily be integrated into any .NET project as an alternative to AES-GCM. It supports .NET Standard 1.3 and up and .NET Framework 3.5 and up. The public API tries to replicate that of .NET Standard 2.1's [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=netstandard-2.1). Implementation is based on libsodium. Neither encryption or decryption allocate and sensitive information is zeroed from memory before freeing resources.

## Usage

### Example

```cs
using AtlasRhythm.Cryptography;
using System.Security.Cryptography;

// Create a new cryptographically secure random number generator
var rng = new RNGCryptoServiceProvider();

// Generate a random key of the appropriate length
var key = new byte[Chacha20Poly1305.KeySize];
rng.GetBytes(key);

// Create the instance
// Note the `using var`, this is necessary to make sure
// the memory containing the key is zeroed after use
using var aead = new Chacha20Poly1305(key);

// Generate a random nonce of the appropriate length
// A nonce must *never* be used twice with the same key
var nonce = new byte[Chacha20Poly1305.NonceSize];
rng.GetBytes(nonce);

// Obtain the plaintext (content to encrypt) and associated data somehow
// The associated data is just used as additional authentication security
// and is optional
var plaintext = ...;
var associatedData = ...;

// Encrypt the plaintext and return a buffer containing
// the ciphertext (encrypted contents) and the authentication tag
var output = aead.Encrypt(nonce, plaintext, associatedData);

// Decrypt and authenticate the previously obtained output
byte[] newPlaintext;
try
{
    newPlaintext = aead.Decrypt(nonce, output, associatedData);
}
catch (CryptographicException ex)
{
    // An exception will be thrown if the authentication tag can't be verified
    // This usually means the contents have been tampered with
}
```

## Tests

The solution contains an extensive test suite using [test vectors from the RFC](https://tools.ietf.org/html/rfc8439#section-2.8.2) and random data.

To run the tests, simply run `dotnet test` from the [Chacha20Poly1305.Tests](Chacha20Poly1305.Tests) directory.

## Benchmarks

The benchmarks compare performance against .NET's [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=netstandard-2.1) and NSec's (libsodium) [Chacha20Poly1305](https://nsec.rocks/docs/api/nsec.cryptography.aeadalgorithm#chacha20poly1305) on .NET 5.0 and CoreRT 5.0.

They can be run from the [Chacha20Poly1305.Benchmarks](Chacha20Poly1305.Benchmarks) directory by running `dotnet run -c Release`.

### Sample results

> Intel Core i7-7700HQ @ 2.8GHz

| Method | Job | Runtime | N | Mean | Error | StdDev | Ratio | RatioSD |
| --- | --- | --- | --- | --: | --: | --: | --: | --: |
| Chacha20Poly1305Roundtrip | .NET Core 5.0 | .NET Core 5.0 | 1024 | 9.293 us | 0.1055 us | 0.0881 us | 1.00 | 0.00 |
| SodiumChacha20Poly1305Roundtrip | .NET Core 5.0 | .NET Core 5.0 | 1024 | 3.501 us | 0.0488 us | 0.0456 us | 0.38 | 0.00 |
| AesGcmRoundtrip | .NET Core 5.0 | .NET Core 5.0 | 1024 | 9.353 us | 0.0537 us | 0.0503 us | 1.01 | 0.01 |
| Chacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 8.985 us | 0.1714 us | 0.1834 us | 0.97 | 0.02 |
| SodiumChacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 3.474 us | 0.0316 us | 0.0296 us | 0.37 | 0.01 |
| AesGcmRoundtrip | CoreRt 5.0 | CoreRt 5.0 | 1024 | 9.546 us | 0.1497 us | 0.1400 us | 1.03 | 0.01 |
|  |  |  |  |  |  |  |  |  |
| Chacha20Poly1305Roundtrip | .NET Core 5.0 | .NET Core 5.0 | 1048576 | 8,404.469 us | 74.4725 us | 66.0179 us | 1.00 | 0.00 |
| SodiumChacha20Poly1305Roundtrip | .NET Core 5.0 | .NET Core 5.0 | 1048576 | 3,058.697 us | 58.1749 us | 59.7414 us | 0.36 | 0.01 |
| AesGcmRoundtrip | .NET Core 5.0 | .NET Core 5.0 | 1048576 | 9,089.818 us | 77.7743 us | 68.9449 us | 1.08 | 0.01 |
| Chacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 8,435.115 us | 94.1931 us | 83.4998 us | 1.00 | 0.01 |
| SodiumChacha20Poly1305Roundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 3,058.478 us | 21.5866 us | 19.1360 us | 0.36 | 0.00 |
| AesGcmRoundtrip | CoreRt 5.0 | CoreRt 5.0 | 1048576 | 9,085.043 us | 114.6314 us | 107.2263 us | 1.08 | 0.01 |

## License

This code is distributed under the terms of the [Apache License (Version 2.0)](LICENSE).
