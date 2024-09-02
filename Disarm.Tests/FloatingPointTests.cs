using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

public class FloatingPointTests : BaseDisarmTest
{
    public FloatingPointTests(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }
    
    [Fact]
    public void FloatingToFromFixedTests()
    {
        var insn = DisassembleAndCheckMnemonic(0x1E02C060, Arm64Mnemonic.SCVTF);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        Assert.Equal(Arm64OperandKind.Immediate, insn.Op2Kind);
        
        Assert.Equal(Arm64Register.S0, insn.Op0Reg);
        Assert.Equal(Arm64Register.W3, insn.Op1Reg);
        Assert.Equal(16, insn.Op2Imm);
        
        Assert.Equal("0x00000000 SCVTF S0, W3, 0x10", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x1E18C060, Arm64Mnemonic.FCVTZS);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        Assert.Equal(Arm64OperandKind.Immediate, insn.Op2Kind);
        
        Assert.Equal(Arm64Register.W0, insn.Op0Reg);
        Assert.Equal(Arm64Register.S3, insn.Op1Reg);
        Assert.Equal(16, insn.Op2Imm);
        
        Assert.Equal("0x00000000 FCVTZS W0, S3, 0x10", insn.ToString());
    }
}