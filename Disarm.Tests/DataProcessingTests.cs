using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

public class DataProcessingTests : BaseDisarmTest
{
    public DataProcessingTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }
    
    [Fact]
    public void DisassemblingBitfieldsWorks()
    {
        var insn = DisassembleAndCheckMnemonic(0x93407E95, Arm64Mnemonic.SXTW);
        Assert.Equal(Arm64Register.X21, insn.Op0Reg);
        Assert.Equal(Arm64Register.W20, insn.Op1Reg);
    }

    [Fact]
    public void DataProcessing2Source() 
        => DisassembleAndCheckMnemonic(0x1AC80D2AU, Arm64Mnemonic.SDIV);

    [Fact]
    public void ConditionalCompareImmediate()
    {
        var insn = DisassembleAndCheckMnemonic(0x7A49B102U, Arm64Mnemonic.CCMP);
        
        Assert.Equal(Arm64Register.W8, insn.Op0Reg);
        Assert.Equal(Arm64Register.W9, insn.Op1Reg);
        Assert.Equal(2, insn.Op2Imm);
        Assert.Equal(Arm64ConditionCode.LT, insn.FinalOpConditionCode);
    }
}
