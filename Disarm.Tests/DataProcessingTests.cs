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
    public void DataProcessing1Source()
    {
        //Mostly just mnemonic checks but with some register checks sprinkled in
        DisassembleAndCheckMnemonic(0x5AC00914, Arm64Mnemonic.REV);
        DisassembleAndCheckMnemonic(0xDAC00D14, Arm64Mnemonic.REV); //but 64-bit
        DisassembleAndCheckMnemonic(0xDAC00914, Arm64Mnemonic.REV32);
        DisassembleAndCheckMnemonic(0xDAC00514, Arm64Mnemonic.REV16);

        Assert.Equal(Arm64Register.X8, DisassembleAndCheckMnemonic(0xDAC01114, Arm64Mnemonic.CLZ).Op1Reg);
        DisassembleAndCheckMnemonic(0xDAC01514, Arm64Mnemonic.CLS);
        
        Assert.Equal(Arm64Register.W20, DisassembleAndCheckMnemonic(0x5AC00114, Arm64Mnemonic.RBIT).Op0Reg);
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

    [Fact]
    public void AddSubWithCarry()
    {
        //These are all one code path except for the mnemonic. So we validate the registers on one and then check only the mnemonic on the others.
        var ins = DisassembleAndCheckMnemonic(0x9A020020, Arm64Mnemonic.ADC);
        
        Assert.Equal(Arm64Register.X0, ins.Op0Reg);
        Assert.Equal(Arm64Register.X1, ins.Op1Reg);
        Assert.Equal(Arm64Register.X2, ins.Op2Reg);
        
        DisassembleAndCheckMnemonic(0xBA020020, Arm64Mnemonic.ADCS);
        DisassembleAndCheckMnemonic(0xDA020020, Arm64Mnemonic.SBC);
        DisassembleAndCheckMnemonic(0xFA020020, Arm64Mnemonic.SBCS);
        
        //And 32-bit
        DisassembleAndCheckMnemonic(0x1A020020, Arm64Mnemonic.ADC);
        DisassembleAndCheckMnemonic(0x3A020020, Arm64Mnemonic.ADCS);
        DisassembleAndCheckMnemonic(0x5A020020, Arm64Mnemonic.SBC);
        DisassembleAndCheckMnemonic(0x7A020020, Arm64Mnemonic.SBCS);
    }
}
