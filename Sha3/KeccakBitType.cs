using System.ComponentModel;

namespace netcracker.Sha3;

public enum KeccakBitType
{
    [Description("128")] K128 = 128, // 0x00000080
    [Description("224")] K224 = 224, // 0x000000E0
    [Description("256")] K256 = 256, // 0x00000100
    [Description("288")] K288 = 288, // 0x00000120
    [Description("384")] K384 = 384, // 0x00000180
    [Description("512")] K512 = 512, // 0x00000200
}