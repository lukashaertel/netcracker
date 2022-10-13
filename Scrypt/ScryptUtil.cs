using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;

namespace netcracker.Scrypt;

public static class ScryptUtil
{
    public static void Scrypt(string password, ReadOnlySpan<byte> salt, int n, int r, int p, Span<byte> dk) =>
        Scrypt(Encoding.UTF8.GetBytes(password), salt, n, r, p, dk);

    public static void Scrypt(byte[] password, ReadOnlySpan<byte> salt, int n, int r, int p, Span<byte> dk)
    {
        if (n < 2 || (n & n - 1) != 0)
            throw new ArgumentException("N must be a power of 2 greater than 1", nameof(n));
        if (n > 16777215 / r)
            throw new ArgumentException("Parameter N is too large", nameof(n));
        if (r > 16777215 / p)
            throw new ArgumentException("Parameter r is too large", nameof(r));
        Span<byte> xy = stackalloc byte[256 * r];
        var vArray = ArrayPool<byte>.Shared.Rent(128 * r * n);
        Span<byte> vSpan = vArray;
        using var mac = new HMACSHA256(password);

        Span<byte> numArray = stackalloc byte[p * 128 * r];
        PBKDF2_SHA256(mac, salt, 1L, numArray);

        for (var index = 0; index < p; ++index)
            SMix(numArray, index * 128 * r, r, n, vSpan, xy);

        PBKDF2_SHA256(mac, numArray, 1L, dk);
        ArrayPool<byte>.Shared.Return(vArray);
    }

    private static unsafe void PBKDF2_SHA256(
        HMACSHA256 mac,
        ReadOnlySpan<byte> salt,
        long iterationCount,
        Span<byte> dk)
    {
        if (dk.Length > (Math.Pow(2.0, 32.0) - 1.0) * 32.0)
            throw new ArgumentException("Requested key length too long");

        var length1 = salt.Length;

        Span<byte> span = stackalloc byte[32];
        Span<byte> destination = stackalloc byte[32];
        Span<byte> numArray = stackalloc byte[length1 + 4];

        var num1 = (int)Math.Ceiling(dk.Length / 32.0);
        var num2 = dk.Length - (num1 - 1) * 32;
        salt.CopyTo(numArray);

        for (var index1 = 1; index1 <= num1; ++index1)
        {
            numArray[length1] = (byte)(index1 >> 24);
            numArray[length1 + 1] = (byte)(index1 >> 16);
            numArray[length1 + 2] = (byte)(index1 >> 8);
            numArray[length1 + 3] = (byte)index1;

            mac.Initialize();
            mac.TryComputeHash(numArray, span, out _);

            span.CopyTo(destination);
            for (long index2 = 1; index2 < iterationCount; ++index2)
            {
                mac.TryComputeHash(span, span, out _);
                for (var index3 = 0; index3 < 32; ++index3)
                    destination[index3] ^= span[index3];
            }

            var length2 = index1 == num1 ? num2 : 32;
            destination[..length2].CopyTo(dk.Slice((index1 - 1) * 32, length2));
        }
    }

    private static void SMix(Span<byte> b, int bi, int r, int n, Span<byte> v, Span<byte> xy)
    {
        const int num1 = 0;
        var num2 = 128 * r;
        b.Slice(bi, num2).CopyTo(xy.Slice(num1, num2));
        for (var index = 0; index < n; ++index)
        {
            var span = xy.Slice(num1, num2);
            span.CopyTo(v.Slice(index * num2, num2));
            BlockMixSalsa8(xy, num1, num2, r);
        }

        for (var index = 0; index < n; ++index)
        {
            var num3 = AsInteger(xy.Slice(num1 + (2 * r - 1) * 64, 4)) & n - 1;
            BlockXor(v.Slice(num3 * num2, num2), xy.Slice(num1, num2));
            BlockMixSalsa8(xy, num1, num2, r);
        }

        {
            var span = xy.Slice(num1, num2);
            span.CopyTo(b.Slice(bi, num2));
        }
    }

    private static unsafe void BlockMixSalsa8(Span<byte> by, int bi, int yi, int r)
    {
        Span<byte> span = stackalloc byte[64];
        by.Slice(bi + (2 * r - 1) * 64, 64).CopyTo(span);
        for (var index = 0; index < 2 * r; ++index)
        {
            BlockXor(by.Slice(index * 64, 64), span);
            Salsa20_8(span);
            span.CopyTo(by.Slice(yi + index * 64, 64));
        }

        for (var index = 0; index < r; ++index)
            by.Slice(yi + index * 2 * 64, 64).CopyTo(by.Slice(bi + index * 64, 64));
        for (var index = 0; index < r; ++index)
            by.Slice(yi + (index * 2 + 1) * 64, 64).CopyTo(by.Slice(bi + (index + r) * 64, 64));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint R7(uint a) => a << 7 | a >> 25;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint R9(uint a) => a << 9 | a >> 23;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint R13(uint a) => a << 13 | a >> 19;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint R18(uint a) => a << 18 | a >> 14;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void Salsa20_8(Span<byte> b)
    {
        fixed (byte* numPtr1 = &b.GetPinnableReference())
        {
            var numPtr2 = stackalloc uint[16];
            Unsafe.CopyBlock(numPtr2, numPtr1, 64);
            for (var index = 0; index < 8; index += 2)
            {
                var numPtr3 = numPtr2 + 4;
                (*numPtr3) ^= R7(numPtr2[0] + numPtr2[12]);
                var numPtr4 = numPtr2 + 8;
                (*numPtr4) ^= R9(numPtr2[4] + numPtr2[0]);
                var numPtr5 = numPtr2 + 12;
                (*numPtr5) ^= R13(numPtr2[8] + numPtr2[4]);
                var numPtr6 = numPtr2;

                var num1 = (int)*numPtr6 ^ (int)R18(numPtr2[12] + numPtr2[8]);
                *numPtr6 = (uint)num1;
                var numPtr7 = numPtr2 + 9;
                (*numPtr7) ^= R7(numPtr2[5] + numPtr2[1]);
                var numPtr8 = numPtr2 + 13;
                (*numPtr8) ^= R9(numPtr2[9] + numPtr2[5]);
                var numPtr9 = numPtr2 + 1;
                (*numPtr9) ^= R13(numPtr2[13] + numPtr2[9]);
                var numPtr10 = numPtr2 + 5;
                (*numPtr10) ^= R18(numPtr2[1] + numPtr2[13]);
                var numPtr11 = numPtr2 + 14;
                (*numPtr11) ^= R7(numPtr2[10] + numPtr2[6]);
                var numPtr12 = numPtr2 + 2;
                (*numPtr12) ^= R9(numPtr2[14] + numPtr2[10]);
                var numPtr13 = numPtr2 + 6;
                (*numPtr13) ^= R13(numPtr2[2] + numPtr2[14]);
                var numPtr14 = numPtr2 + 10;
                (*numPtr14) ^= R18(numPtr2[6] + numPtr2[2]);
                var numPtr15 = numPtr2 + 3;
                (*numPtr15) ^= R7(numPtr2[15] + numPtr2[11]);
                var numPtr16 = numPtr2 + 7;
                (*numPtr16) ^= R9(numPtr2[3] + numPtr2[15]);
                var numPtr17 = numPtr2 + 11;
                (*numPtr17) ^= R13(numPtr2[7] + numPtr2[3]);
                var numPtr18 = numPtr2 + 15;
                (*numPtr18) ^= R18(numPtr2[11] + numPtr2[7]);
                var numPtr19 = numPtr2 + 1;
                (*numPtr19) ^= R7(numPtr2[0] + numPtr2[3]);
                var numPtr20 = numPtr2 + 2;
                (*numPtr20) ^= R9(numPtr2[1] + numPtr2[0]);
                var numPtr21 = numPtr2 + 3;
                (*numPtr21) ^= R13(numPtr2[2] + numPtr2[1]);
                var numPtr22 = numPtr2;

                var num2 = (int)*numPtr22 ^ (int)R18(numPtr2[3] + numPtr2[2]);
                *numPtr22 = (uint)num2;
                var numPtr23 = numPtr2 + 6;
                (*numPtr23) ^= R7(numPtr2[5] + numPtr2[4]);
                var numPtr24 = numPtr2 + 7;
                (*numPtr24) ^= R9(numPtr2[6] + numPtr2[5]);
                var numPtr25 = numPtr2 + 4;
                (*numPtr25) ^= R13(numPtr2[7] + numPtr2[6]);
                var numPtr26 = numPtr2 + 5;
                (*numPtr26) ^= R18(numPtr2[4] + numPtr2[7]);
                var numPtr27 = numPtr2 + 11;
                (*numPtr27) ^= R7(numPtr2[10] + numPtr2[9]);
                var numPtr28 = numPtr2 + 8;
                (*numPtr28) ^= R9(numPtr2[11] + numPtr2[10]);
                var numPtr29 = numPtr2 + 9;
                (*numPtr29) ^= R13(numPtr2[8] + numPtr2[11]);
                var numPtr30 = numPtr2 + 10;
                (*numPtr30) ^= R18(numPtr2[9] + numPtr2[8]);
                var numPtr31 = numPtr2 + 12;
                (*numPtr31) ^= R7(numPtr2[15] + numPtr2[14]);
                var numPtr32 = numPtr2 + 13;
                (*numPtr32) ^= R9(numPtr2[12] + numPtr2[15]);
                var numPtr33 = numPtr2 + 14;
                (*numPtr33) ^= R13(numPtr2[13] + numPtr2[12]);
                var numPtr34 = numPtr2 + 15;
                (*numPtr34) ^= R18(numPtr2[14] + numPtr2[13]);
            }

            if (Avx2.IsSupported)
            {
                var ap1 = (Vector256<uint>*)numPtr1;
                var ap2 = (Vector256<uint>*)numPtr2;
                var vector256 = Avx2.Add(ap1[0], ap2[0]);
                ap1[0] = vector256;
                ap1[1] = Avx2.Add(ap1[1], ap2[1]);
            }
            else if (Sse2.IsSupported)
            {
                var ap1 = (Vector128<uint>*)numPtr1;
                var ap2 = (Vector128<uint>*)numPtr2;
                ap1[0] = Sse2.Add(ap1[0], ap2[0]);
                ap1[1] = Sse2.Add(ap1[1], ap2[1]);
                ap1[2] = Sse2.Add(ap1[2], ap2[2]);
                ap1[3] = Sse2.Add(ap1[3], ap2[3]);
            }
            else
            {
                for (var index = 0; index < 16; ++index)
                {
                    var numPtr35 = (uint*)numPtr1 + index;
                    (*numPtr35) += numPtr2[index];
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void BlockXor(ReadOnlySpan<byte> s, Span<byte> d)
    {
        if (Avx2.IsSupported)
        {
            unsafe
            {
                fixed (byte* sp = &s.GetPinnableReference())
                fixed (byte* dp = &d.GetPinnableReference())
                {
                    var svp = (Vector256<byte>*)sp;
                    var dvp = (Vector256<byte>*)dp;

                    for (var i = 0; i < s.Length / 32; i++)
                    {
                        *dvp = Avx2.Xor(*dvp, *svp);
                        svp++;
                        dvp++;
                    }
                }
            }
        }
        else if (Sse2.IsSupported)
        {
            unsafe
            {
                fixed (byte* sp = &s.GetPinnableReference())
                fixed (byte* dp = &d.GetPinnableReference())
                {
                    var svp = (Vector128<byte>*)sp;
                    var dvp = (Vector128<byte>*)dp;

                    for (var i = 0; i < s.Length / 16; i++)
                    {
                        *dvp = Sse2.Xor(*dvp, *svp);
                        svp++;
                        dvp++;
                    }
                }
            }
        }
        else
        {
            for (var index = 0; index < s.Length; ++index)
                d[index] ^= s[index];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int AsInteger(ReadOnlySpan<byte> b) =>
        BitConverter.ToInt32(b);
}