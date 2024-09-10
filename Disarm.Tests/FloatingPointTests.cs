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

    [Fact]
    public void ConditionalCompareTests()
    {
        var insn = DisassembleAndCheckMnemonic(0x1E210401, Arm64Mnemonic.FCCMP);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        Assert.Equal(Arm64OperandKind.Immediate, insn.Op2Kind);
        
        Assert.Equal(Arm64Register.S0, insn.Op0Reg);
        Assert.Equal(Arm64Register.S1, insn.Op1Reg);
        Assert.Equal(1, insn.Op2Imm);
        
        Assert.Equal(Arm64ConditionCode.EQ, insn.FinalOpConditionCode);
        
        Assert.Equal("0x00000000 FCCMP S0, S1, 0x1, EQ", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x1E614411, Arm64Mnemonic.FCCMPE);
        
        Assert.Equal(Arm64Register.D0, insn.Op0Reg);
        Assert.Equal(Arm64Register.D1, insn.Op1Reg);
        Assert.Equal(1, insn.Op2Imm);
        
        Assert.Equal(Arm64ConditionCode.MI, insn.FinalOpConditionCode);
        
        Assert.Equal("0x00000000 FCCMPE D0, D1, 0x1, MI", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x1EE10401, Arm64Mnemonic.FCCMP);
        
        Assert.Equal(Arm64Register.H0, insn.Op0Reg);
        Assert.Equal(Arm64Register.H1, insn.Op1Reg);
    }
}