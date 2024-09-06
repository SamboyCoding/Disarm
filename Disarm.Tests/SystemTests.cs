using Xunit.Abstractions;

namespace Disarm.Tests;

public class SystemTests : BaseDisarmTest
{
    public SystemTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void TestMnemonics()
    {
        DisassembleAndCheckMnemonic(0xD5031000, Arm64Mnemonic.WFET);
        DisassembleAndCheckMnemonic(0xD5031020, Arm64Mnemonic.WFIT);
        DisassembleAndCheckMnemonic(0xD5080000, Arm64Mnemonic.SYS);
        DisassembleAndCheckMnemonic(0xD5280000, Arm64Mnemonic.SYSL);
        DisassembleAndCheckMnemonic(0xD5300000, Arm64Mnemonic.MRS);
        DisassembleAndCheckMnemonic(0xD5100000, Arm64Mnemonic.MSR);
    }
}