using Xunit.Abstractions;

namespace Disarm.Tests;

public class BarriersTests : BaseDisarmTest
{
    public BarriersTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void TestMnemonics()
    {
        Assert.Equal(2, DisassembleAndCheckMnemonic(0xD503325F, Arm64Mnemonic.CLREX).Op0Imm);
        Assert.Equal(0b1111, DisassembleAndCheckMnemonic(0xD5033FBF, Arm64Mnemonic.DMB).Op0Imm); // flag SY eq 0b1111
        DisassembleAndCheckMnemonic(0xD5033FDF, Arm64Mnemonic.ISB);
        DisassembleAndCheckMnemonic(0xD50330FF, Arm64Mnemonic.SB);
        DisassembleAndCheckMnemonic(0xD5033A3F, Arm64Mnemonic.DSBWithFEATXS);
        DisassembleAndCheckMnemonic(0xD5033B9F, Arm64Mnemonic.DSB);
        DisassembleAndCheckMnemonic(0xD503308F, Arm64Mnemonic.SSBB);
    }
}