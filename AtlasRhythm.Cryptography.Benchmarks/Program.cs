using BenchmarkDotNet.Running;
using System.Linq;

namespace AtlasRhythm.Cryptography.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            var argsLower = args.Select(a => a.ToLower()).ToArray();

            if (argsLower.Contains("chacha20poly1305")) BenchmarkRunner.Run<Chacha20Poly1305Benchmarks>();
        }
    }
}
