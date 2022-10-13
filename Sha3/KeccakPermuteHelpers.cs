using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace netcracker.Sha3;

internal sealed class KeccakPermuteHelpers
{
    private const int KeccakRounds = 24;

    internal static readonly ulong[] RoundConstants = new ulong[24]
    {
        1UL,
        32898UL,
        9223372036854808714UL,
        9223372039002292224UL,
        32907UL,
        2147483649UL,
        9223372039002292353UL,
        9223372036854808585UL,
        138UL,
        136UL,
        2147516425UL,
        2147483658UL,
        2147516555UL,
        9223372036854775947UL,
        9223372036854808713UL,
        9223372036854808579UL,
        9223372036854808578UL,
        9223372036854775936UL,
        32778UL,
        9223372039002259466UL,
        9223372039002292353UL,
        9223372036854808704UL,
        2147483649UL,
        9223372039002292232UL
    };

    private KeccakPermuteHelpers()
    {
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong AddStateBuffer(Span<byte> bs, int off) =>
        BinaryPrimitives.ReadUInt64LittleEndian(bs[off..]);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void Extract(byte[] extracted, ulong[] state)
    {
        var off = 0;
        for (var index = 0; index < extracted.Length / 8; ++index)
        {
            ExtractStateBuffer(state[index], extracted, off);
            off += 8;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void ExtractStateBuffer(ulong n, byte[] bs, int off) =>
        BinaryPrimitives.WriteUInt64LittleEndian(bs.AsSpan(off), n);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void Permute(ulong[] state)
    {
        var bytes = MemoryMarshal.AsBytes(state.AsSpan());
        var permuteState = MemoryMarshal.Read<PermuteState>(bytes);
        var c0 = default(ulong);
        var c1 = default(ulong);
        for (var round = 0; round < 24; ++round)
        {
            Theta(ref permuteState, ref c0, ref c1);
            RhoPi(ref permuteState, ref c0, ref c1);
            Chi(ref permuteState, ref c0, ref c1);
            Iota(ref permuteState, round);
        }

        MemoryMarshal.Write(bytes, ref permuteState);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Theta(ref PermuteState permuteState, ref ulong c0, ref ulong c1)
    {
        c0 = permuteState.A00 ^ permuteState.A05 ^ permuteState.A10 ^ permuteState.A15 ^ permuteState.A20;
        c1 = permuteState.A01 ^ permuteState.A06 ^ permuteState.A11 ^ permuteState.A16 ^ permuteState.A21;
        var x1 = permuteState.A02 ^ permuteState.A07 ^ permuteState.A12 ^ permuteState.A17 ^ permuteState.A22;
        var x2 = permuteState.A03 ^ permuteState.A08 ^ permuteState.A13 ^ permuteState.A18 ^ permuteState.A23;
        var x3 = permuteState.A04 ^ permuteState.A09 ^ permuteState.A14 ^ permuteState.A19 ^ permuteState.A24;
        var num1 = ShiftULongLeft(c1, 1) ^ x3;
        var num2 = ShiftULongLeft(x1, 1) ^ c0;
        var num3 = ShiftULongLeft(x2, 1) ^ c1;
        var num4 = ShiftULongLeft(x3, 1) ^ x1;
        var num5 = ShiftULongLeft(c0, 1) ^ x2;
        permuteState.A00 ^= num1;
        permuteState.A05 ^= num1;
        permuteState.A10 ^= num1;
        permuteState.A15 ^= num1;
        permuteState.A20 ^= num1;
        permuteState.A01 ^= num2;
        permuteState.A06 ^= num2;
        permuteState.A11 ^= num2;
        permuteState.A16 ^= num2;
        permuteState.A21 ^= num2;
        permuteState.A02 ^= num3;
        permuteState.A07 ^= num3;
        permuteState.A12 ^= num3;
        permuteState.A17 ^= num3;
        permuteState.A22 ^= num3;
        permuteState.A03 ^= num4;
        permuteState.A08 ^= num4;
        permuteState.A13 ^= num4;
        permuteState.A18 ^= num4;
        permuteState.A23 ^= num4;
        permuteState.A04 ^= num5;
        permuteState.A09 ^= num5;
        permuteState.A14 ^= num5;
        permuteState.A19 ^= num5;
        permuteState.A24 ^= num5;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void RhoPi(ref PermuteState permuteState, ref ulong c0, ref ulong c1)
    {
        c1 = ShiftULongLeft(permuteState.A01, 1);
        permuteState.A01 = ShiftULongLeft(permuteState.A06, 44);
        permuteState.A06 = ShiftULongLeft(permuteState.A09, 20);
        permuteState.A09 = ShiftULongLeft(permuteState.A22, 61);
        permuteState.A22 = ShiftULongLeft(permuteState.A14, 39);
        permuteState.A14 = ShiftULongLeft(permuteState.A20, 18);
        permuteState.A20 = ShiftULongLeft(permuteState.A02, 62);
        permuteState.A02 = ShiftULongLeft(permuteState.A12, 43);
        permuteState.A12 = ShiftULongLeft(permuteState.A13, 25);
        permuteState.A13 = ShiftULongLeft(permuteState.A19, 8);
        permuteState.A19 = ShiftULongLeft(permuteState.A23, 56);
        permuteState.A23 = ShiftULongLeft(permuteState.A15, 41);
        permuteState.A15 = ShiftULongLeft(permuteState.A04, 27);
        permuteState.A04 = ShiftULongLeft(permuteState.A24, 14);
        permuteState.A24 = ShiftULongLeft(permuteState.A21, 2);
        permuteState.A21 = ShiftULongLeft(permuteState.A08, 55);
        permuteState.A08 = ShiftULongLeft(permuteState.A16, 45);
        permuteState.A16 = ShiftULongLeft(permuteState.A05, 36);
        permuteState.A05 = ShiftULongLeft(permuteState.A03, 28);
        permuteState.A03 = ShiftULongLeft(permuteState.A18, 21);
        permuteState.A18 = ShiftULongLeft(permuteState.A17, 15);
        permuteState.A17 = ShiftULongLeft(permuteState.A11, 10);
        permuteState.A11 = ShiftULongLeft(permuteState.A07, 6);
        permuteState.A07 = ShiftULongLeft(permuteState.A10, 3);
        permuteState.A10 = c1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Chi(ref PermuteState permuteState, ref ulong c0, ref ulong c1)
    {
        c0 = permuteState.A00 ^ ~permuteState.A01 & permuteState.A02;
        c1 = permuteState.A01 ^ ~permuteState.A02 & permuteState.A03;
        permuteState.A02 ^= ~permuteState.A03 & permuteState.A04;
        permuteState.A03 ^= ~permuteState.A04 & permuteState.A00;
        permuteState.A04 ^= ~permuteState.A00 & permuteState.A01;
        permuteState.A00 = c0;
        permuteState.A01 = c1;
        c0 = permuteState.A05 ^ ~permuteState.A06 & permuteState.A07;
        c1 = permuteState.A06 ^ ~permuteState.A07 & permuteState.A08;
        permuteState.A07 ^= ~permuteState.A08 & permuteState.A09;
        permuteState.A08 ^= ~permuteState.A09 & permuteState.A05;
        permuteState.A09 ^= ~permuteState.A05 & permuteState.A06;
        permuteState.A05 = c0;
        permuteState.A06 = c1;
        c0 = permuteState.A10 ^ ~permuteState.A11 & permuteState.A12;
        c1 = permuteState.A11 ^ ~permuteState.A12 & permuteState.A13;
        permuteState.A12 ^= ~permuteState.A13 & permuteState.A14;
        permuteState.A13 ^= ~permuteState.A14 & permuteState.A10;
        permuteState.A14 ^= ~permuteState.A10 & permuteState.A11;
        permuteState.A10 = c0;
        permuteState.A11 = c1;
        c0 = permuteState.A15 ^ ~permuteState.A16 & permuteState.A17;
        c1 = permuteState.A16 ^ ~permuteState.A17 & permuteState.A18;
        permuteState.A17 ^= ~permuteState.A18 & permuteState.A19;
        permuteState.A18 ^= ~permuteState.A19 & permuteState.A15;
        permuteState.A19 ^= ~permuteState.A15 & permuteState.A16;
        permuteState.A15 = c0;
        permuteState.A16 = c1;
        c0 = permuteState.A20 ^ ~permuteState.A21 & permuteState.A22;
        c1 = permuteState.A21 ^ ~permuteState.A22 & permuteState.A23;
        permuteState.A22 ^= ~permuteState.A23 & permuteState.A24;
        permuteState.A23 ^= ~permuteState.A24 & permuteState.A20;
        permuteState.A24 ^= ~permuteState.A20 & permuteState.A21;
        permuteState.A20 = c0;
        permuteState.A21 = c1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Iota(ref PermuteState permuteState, int round) =>
        permuteState.A00 ^= RoundConstants[round];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ShiftULongLeft(ulong x, byte y) => x << y | x >> 64 - y;
}