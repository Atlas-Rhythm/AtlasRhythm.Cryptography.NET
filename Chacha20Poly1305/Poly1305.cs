// Copyright 2020 Atlas Rhythm
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Numerics;

namespace Chacha20Poly1305
{
    internal static class Poly1305
    {
        public const int KeySize = 256 / 8;
        public const int TagSize = 128 / 8;

        private const int RSize = 16;
        private const int SSize = 16;

        private static readonly BigInteger P = BigInteger.Pow(new BigInteger(2), 130) - 5;

        public static void Mac(byte[] message, byte[] key, byte[] tag)
        {
            var rBytes = new byte[RSize];
            Array.Copy(key, rBytes, RSize);
            rBytes[3] &= 15;
            rBytes[7] &= 15;
            rBytes[11] &= 15;
            rBytes[15] &= 15;
            rBytes[4] &= 252;
            rBytes[8] &= 252;
            rBytes[12] &= 252;
            var r = new BigInteger(rBytes);

            var sBytes = new byte[SSize];
            Array.Copy(key, RSize, sBytes, 0, SSize);
            var s = new BigInteger(sBytes);

            var a = new BigInteger(0);

            for (var i = 0; i < message.Length; i += TagSize)
            {
                var nBytes = new byte[TagSize + 1];
                var messageLength = Math.Max(TagSize, message.Length - i);
                Array.Copy(message, i, nBytes, 0, messageLength);
                nBytes[messageLength] = 0x01;
                var n = new BigInteger(nBytes);

                a += n;
                a = r * a % P;
            }

            a += s;

            Array.Copy(a.ToByteArray(), tag, TagSize);
        }
    }
}
