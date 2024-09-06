using Xunit.Abstractions;

namespace Disarm.Tests;

public class PstateTests : BaseDisarmTest
{
    public PstateTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void TestMnemonics()
    {
        DisassembleAndCheckMnemonic(0xD500401F, Arm64Mnemonic.CFINV);
        DisassembleAndCheckMnemonic(0xD500403F, Arm64Mnemonic.XAFLAG);
        DisassembleAndCheckMnemonic(0xD500405F, Arm64Mnemonic.AXFLAG);
    }
}