using Xunit.Abstractions;

namespace Disarm.Tests;

public class BranchTests : BaseDisarmTest
{
    public BranchTests(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }

    [Fact]
    public void BranchAddressesAreCorrect()
    {
        ulong address = 0x023b6a90;
        var bytes = new byte[] { 0x3f, 0x69, 0xa2, 0x17 };
        var insn = Disassembler.Disassemble(bytes, address).Single();
        
        Assert.Equal(Arm64Mnemonic.B, insn.Mnemonic);
        Assert.Equal(0xc50f8cU, insn.BranchTarget);
    }
}