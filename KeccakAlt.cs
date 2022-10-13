using netcracker.Sha3;

namespace netcracker;

public class KeccakAlt : SHA3Core.Keccak.Keccak
{
    public KeccakAlt(SHA3Core.Enums.KeccakBitType bitType) : base(bitType)
    {
    }

    public byte[] HashBytes(byte[] bytesToHash, int length)
    {
        Initialize((int)HashType.Keccak);
        Absorb(bytesToHash, 0, length);
        Partial(bytesToHash, 0, length);

        return Squeeze();
    }
}