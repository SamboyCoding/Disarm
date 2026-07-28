using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

public class FloatingPointTests : BaseDisarmTest
{
    public FloatingPointTests(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }
    
    [Fact]
    public void DataProcessingThreeSourceTests()
    {
        var insn = DisassembleAndCheckMnemonic(0x1F031041, Arm64Mnemonic.FMADD);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op2Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op3Kind);
        
        Assert.Equal(Arm64Register.S1, insn.Op0Reg);
        Assert.Equal(Arm64Register.S2, insn.Op1Reg);
        Assert.Equal(Arm64Register.S3, insn.Op2Reg);
        Assert.Equal(Arm64Register.S4, insn.Op3Reg);
        
        Assert.Equal("0x00000000 FMADD S1, S2, S3, S4", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x1F439041, Arm64Mnemonic.FMSUB);
        
        Assert.Equal(Arm64Register.D1, insn.Op0Reg);
        Assert.Equal(Arm64Register.D2, insn.Op1Reg);
        Assert.Equal(Arm64Register.D3, insn.Op2Reg);
        Assert.Equal(Arm64Register.D4, insn.Op3Reg);
        
        insn = DisassembleAndCheckMnemonic(0x1FE20C20, Arm64Mnemonic.FNMADD);
        
        Assert.Equal(Arm64Register.H0, insn.Op0Reg);
        Assert.Equal(Arm64Register.H1, insn.Op1Reg);
        Assert.Equal(Arm64Register.H2, insn.Op2Reg);
        Assert.Equal(Arm64Register.H3, insn.Op3Reg);

        DisassembleAndCheckMnemonic(0x1F228C20, Arm64Mnemonic.FNMSUB);
    }

}
