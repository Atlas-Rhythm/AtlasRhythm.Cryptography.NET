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

namespace Chacha20Poly1305
{
    internal static unsafe class Chacha20
    {
        public const int KeySize = 256 / 8;
        public const int NonceSize = 96 / 8;

        public const int StateSize = 16;
        public const int StateBytesSize = StateSize * sizeof(uint);

        public static void State(uint* state, byte* key, uint counter, byte* nonce)
        {
            state[ 0] = 0x61707865;
            state[ 1] = 0x3320646e;
            state[ 2] = 0x79622d32;
            state[ 3] = 0x6b206574;

            state[ 4] = Memory.U8ToU32(key                   );
            state[ 5] = Memory.U8ToU32(key +     sizeof(uint));
            state[ 6] = Memory.U8ToU32(key + 2 * sizeof(uint));
            state[ 7] = Memory.U8ToU32(key + 3 * sizeof(uint));
            state[ 8] = Memory.U8ToU32(key + 4 * sizeof(uint));
            state[ 9] = Memory.U8ToU32(key + 5 * sizeof(uint));
            state[10] = Memory.U8ToU32(key + 6 * sizeof(uint));
            state[11] = Memory.U8ToU32(key + 7 * sizeof(uint));

            state[12] = counter;

            state[13] = Memory.U8ToU32(nonce                   );
            state[14] = Memory.U8ToU32(nonce +     sizeof(uint));
            state[15] = Memory.U8ToU32(nonce + 2 * sizeof(uint));
        }

        public static void Cipher(uint* state, uint* x, byte* bytes, byte* data, int size)
        {
            int i;

            while (true)
            {
                Block(state, x, bytes);
                state[12]++;
                
                if (size <= StateBytesSize)
                {
                    for (i = 0; i < size; ++i) data[i] ^= bytes[i];
                    return;
                }

                for (i = 0; i < StateBytesSize; ++i) data[i] ^= bytes[i];

                size -= StateBytesSize;
                data += StateBytesSize;
            }
        }

        public static void Block(uint* state, uint* x, byte* bytes)
        {
            int i;

            for (i = 0; i < StateSize; ++i) x[i] = state[i];

            DoubleRound(x);
            DoubleRound(x);
            DoubleRound(x);
            DoubleRound(x);
            DoubleRound(x);
            DoubleRound(x);
            DoubleRound(x);
            DoubleRound(x);
            DoubleRound(x);
            DoubleRound(x);

            for (i = 0; i < StateSize; ++i) Memory.U32ToU8(x[i] + state[i], bytes + i * sizeof(uint));
        }

        private static void DoubleRound(uint* state)
        {
            QuarterRound(state, 0, 4,  8, 12);
            QuarterRound(state, 1, 5,  9, 13);
            QuarterRound(state, 2, 6, 10, 14);
            QuarterRound(state, 3, 7, 11, 15);
            QuarterRound(state, 0, 5, 10, 15);
            QuarterRound(state, 1, 6, 11, 12);
            QuarterRound(state, 2, 7,  8, 13);
            QuarterRound(state, 3, 4,  9, 14);
        }

        private static void QuarterRound(uint* state, int a, int b, int c, int d)
        {
            state[a] += state[b]; state[d] ^= state[a]; state[d] = state[d].LeftRoll(16);
            state[c] += state[d]; state[b] ^= state[c]; state[b] = state[b].LeftRoll(12);
            state[a] += state[b]; state[d] ^= state[a]; state[d] = state[d].LeftRoll( 8);
            state[c] += state[d]; state[b] ^= state[c]; state[b] = state[b].LeftRoll( 7);
        }
    }
}
