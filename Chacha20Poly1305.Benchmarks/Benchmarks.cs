using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using System;

namespace Chacha20Poly1305.Benchmarks
{
    [SimpleJob(RuntimeMoniker.NetCoreApp50, baseline: true)]
    [SimpleJob(RuntimeMoniker.CoreRt50)]
    [SimpleJob(RuntimeMoniker.Net48)]
    [SimpleJob(RuntimeMoniker.Mono)]
    public class Benchmarks
    {
        private Chacha20Poly1305 aead;

        private byte[] key;
        private byte[] nonce;
        private byte[] plaintext;
        private byte[] ciphertext;
        private byte[] computedPlaintext;
        private byte[] tag;
        private byte[] associatedData;

        [Params(1024, 1024 * 1024)]
        public int N;

        [Benchmark(Baseline = true)]
        public void Roundtrip()
        {
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            aead.Decrypt(nonce, ciphertext, tag, computedPlaintext, associatedData);
        }

        [Benchmark]
        public void Encrypt()
        {
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        }

        [Benchmark]
        public void Decrypt()
        {
            aead.Decrypt(nonce, ciphertext, tag, computedPlaintext, associatedData);
        }

        private void Setup()
        {
            var rng = new Random(2112);

            key = new byte[Chacha20Poly1305.KeySize];
            rng.NextBytes(key);

            nonce = new byte[Chacha20Poly1305.NonceSize];
            rng.NextBytes(nonce);

            plaintext = new byte[N];
            rng.NextBytes(plaintext);

            ciphertext = new byte[N];

            tag = new byte[Chacha20Poly1305.TagSize];

            associatedData = new byte[12];
            rng.NextBytes(associatedData);

            aead = new Chacha20Poly1305(key);
        }

        [GlobalSetup(Target = nameof(Roundtrip))]
        public void SetupRoundtrip()
        {
            Setup();
            computedPlaintext = new byte[N];
        }

        [GlobalSetup(Target = nameof(Encrypt))]
        public void SetupEncrypt()
        {
            Setup();
        }

        [GlobalSetup(Target = nameof(Decrypt))]
        public void SetupDecrypt()
        {
            Setup();
            computedPlaintext = new byte[N];
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            aead.Dispose();
        }
    }
}
