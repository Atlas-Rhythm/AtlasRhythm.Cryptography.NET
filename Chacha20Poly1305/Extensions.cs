namespace Chacha20Poly1305
{
    internal static class Extensions
    {
        public static uint LeftRoll(this uint lhs, int rhs) => (lhs << rhs) | (lhs >> (sizeof(uint) * 8 - rhs));
    }
}
