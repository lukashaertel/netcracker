using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace netcracker.Sha3;

public static class Converters
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] ConvertStringToBytes(string hash) => Encoding.ASCII.GetBytes(hash);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static string ConvertBytesToStringHash(byte[] hashBytes) =>
        BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToLower();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int ConvertBitLengthToRate(int bitLength) => (1600 - (bitLength << 1)) / 8;
}