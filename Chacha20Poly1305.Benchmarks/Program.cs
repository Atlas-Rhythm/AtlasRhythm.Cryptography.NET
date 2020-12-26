using BenchmarkDotNet.Running;

namespace Chacha20Poly1305.Benchmarks
{
    class Program
    {
        static void Main(string[] _) => BenchmarkRunner.Run(typeof(Program).Assembly);
    }
}
