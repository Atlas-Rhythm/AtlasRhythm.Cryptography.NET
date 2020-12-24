using System;

namespace Chacha20Poly1305
{
    internal static class Chacha20
    {
        private const int Rounds = 20;
        private const int StateLength = 16;
        private const int StateBytesLength = StateLength * sizeof(uint);

        public static void Cipher(byte[] key, uint counter, byte[] nonce, byte[] data)
        {
            for (var i = 0; i < data.Length / StateBytesLength; i++)
            {
                var keyStream = Block(key, counter + (uint)i, nonce);

                for (int dataI = i * StateBytesLength, keyStreamI = 0;
                    dataI < data.Length && keyStreamI < StateBytesLength;
                    dataI++, keyStreamI++)
                {
                    data[dataI] ^= keyStream[keyStreamI];
                }
            }
        }

        public static byte[] Block(byte[] key, uint counter, byte[] nonce)
        {
            var state = new uint[]
            {
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                LittleEndianBitConverter.ToUInt32(key, 0 * sizeof(uint)), LittleEndianBitConverter.ToUInt32(key, 1 * sizeof(uint)), LittleEndianBitConverter.ToUInt32(key, 2 * sizeof(uint)), LittleEndianBitConverter.ToUInt32(key, 3 * sizeof(uint)),
                LittleEndianBitConverter.ToUInt32(key, 4 * sizeof(uint)), LittleEndianBitConverter.ToUInt32(key, 5 * sizeof(uint)), LittleEndianBitConverter.ToUInt32(key, 6 * sizeof(uint)), LittleEndianBitConverter.ToUInt32(key, 7 * sizeof(uint)),
                counter, LittleEndianBitConverter.ToUInt32(nonce, 0 * sizeof(uint)), LittleEndianBitConverter.ToUInt32(nonce, 1 * sizeof(uint)), LittleEndianBitConverter.ToUInt32(nonce, 2 * sizeof(uint))
            };
            var initialState = new uint[StateLength];
            Array.Copy(state, initialState, StateLength);

            for (var i = 0; i < Rounds / 2; i++)
            {
                DoubleRound(state);
            }

            for (var i = 0; i < StateLength; i++)
            {
                state[i] += initialState[i];
            }

            var stateBytes = new byte[StateBytesLength];
            for (var i = 0; i < 16; i++)
            {
                var bytes = LittleEndianBitConverter.GetBytes(state[i]);
                Array.Copy(bytes, 0, stateBytes, i * sizeof(uint), sizeof(uint));
            }
            return stateBytes;
        }

        private static void QuarterRound(uint[] state, int a, int b, int c, int d)
        {
            state[a] += state[b]; state[d] ^= state[a]; state[d] = state[d].LeftRoll(16);
            state[c] += state[d]; state[b] ^= state[c]; state[b] = state[b].LeftRoll(12);
            state[a] += state[b]; state[d] ^= state[a]; state[d] = state[d].LeftRoll(8);
            state[c] += state[d]; state[b] ^= state[c]; state[b] = state[b].LeftRoll(7);
        }

        private static void DoubleRound(uint[] state)
        {
            QuarterRound(state, 0, 4, 8, 12);
            QuarterRound(state, 1, 5, 9, 13);
            QuarterRound(state, 2, 6, 10, 14);
            QuarterRound(state, 3, 7, 11, 15);
            QuarterRound(state, 0, 5, 10, 15);
            QuarterRound(state, 1, 6, 11, 12);
            QuarterRound(state, 2, 7, 8, 13);
            QuarterRound(state, 3, 4, 9, 14);
        }
    }
}
