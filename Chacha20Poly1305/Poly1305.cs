using System;
using System.Numerics;

namespace Chacha20Poly1305
{
    internal static class Poly1305
    {
        private const int NumLength = 16;
        private static readonly BigInteger P = BigInteger.Pow(new BigInteger(2), 130) - 5;

        public static byte[] Mac(byte[] data, byte[] key)
        {
            var rBytes = new byte[NumLength];
            Array.Copy(key, rBytes, NumLength);
            rBytes[3] &= 15;
            rBytes[7] &= 15;
            rBytes[11] &= 15;
            rBytes[15] &= 15;
            rBytes[4] &= 252;
            rBytes[8] &= 252;
            rBytes[12] &= 252;
            var r = new BigInteger(rBytes);

            var sBytes = new byte[NumLength];
            Array.Copy(key, NumLength, sBytes, 0, NumLength);
            var s = new BigInteger(sBytes);

            var a = new BigInteger(0);

            for (var i = 0; i < data.Length; i += NumLength)
            {
                var nBytes = new byte[NumLength + 1];
                var dataLength = Math.Max(NumLength, data.Length - i);
                Array.Copy(data, i, nBytes, 0, dataLength);
                nBytes[dataLength] = 0x01;
                var n = new BigInteger(nBytes);

                a += n;
                a = r * a % P;
            }

            a += s;

            return a.ToByteArray();
        }
    }
}
