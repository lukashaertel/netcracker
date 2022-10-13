using System;
using System.Runtime.CompilerServices;

namespace netcracker.Sha3;

public class Keccak1600
{
    public readonly int RateBytes;
    public readonly int OutputLength;
    private int _blockSize;
    private ulong[] _state;
    private int _hashType;
    private byte[] _extracted;

    public Keccak1600(int bits)
    {
        RateBytes = Converters.ConvertBitLengthToRate(bits);
        OutputLength = bits / 8;
    }

    public Keccak1600(KeccakBitType bitType) : this((int)bitType)
    {
    }

    public void Initialize(int hashType)
    {
        _hashType = hashType;
        _blockSize = 0;
        _state = new ulong[25];
        _extracted = new byte[RateBytes];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected void Absorb(Span<byte> input)
    {
        var size = input.Length;
        var num = 0;
        var off = 0;
        while (size > 0)
        {
            _blockSize = Math.Min(size, RateBytes);
            for (var index = 0; index < _blockSize / 8; ++index)
            {
                _state[index] ^= KeccakPermuteHelpers.AddStateBuffer(input, off);
                off += 8;
            }

            size -= _blockSize;
            if (_blockSize == RateBytes)
            {
                KeccakPermuteHelpers.Permute(_state);
                num += RateBytes;
                _blockSize = 0;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected void Partial(Span<byte> input)
    {
        var length = input.Length % RateBytes % 8;
        var index = input.Length % RateBytes / 8;
        Span<byte> numArray = stackalloc byte[8];
        input[^length..].CopyTo(numArray[..length]);
        numArray[length] = (byte)_hashType;
        _state[index] ^= KeccakPermuteHelpers.AddStateBuffer(numArray, 0);
        _state[RateBytes - 1 >> 3] ^= 9223372036854775808UL;
        KeccakPermuteHelpers.Permute(_state);
        KeccakPermuteHelpers.Extract(_extracted, _state);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected void Squeeze(Span<byte> result)
    {
        var outputLength = OutputLength;
        while (outputLength > 0)
        {
            _blockSize = Math.Min(outputLength, RateBytes);
            _extracted[.._blockSize].CopyTo(result[.._blockSize]);
            outputLength -= _blockSize;
            if (outputLength > 0)
                KeccakPermuteHelpers.Permute(_state);
        }
    }

    public void HashToBytes(Span<byte> bytesToHash, Span<byte> result)
    {
        if (result.Length != OutputLength)
            throw new ArgumentException("Incompatible length, result is not of output length", nameof(result));
        Initialize((int)HashType.Keccak);
        Absorb(bytesToHash);
        Partial(bytesToHash);
        Squeeze(result);
    }
}