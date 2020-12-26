using BenchmarkDotNet.Running;

namespace AtlasRhythm.Cryptography.Benchmarks
{
    class Program
    {
        static void Main(string[] _) => BenchmarkRunner.Run(typeof(Program).Assembly);
    }
}
