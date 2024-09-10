using Disarm.InternalDisassembly;
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

    [Fact]
    public void TestRetFamily()
    {
        var insn = DisassembleAndCheckMnemonic(0xD65F03A0, Arm64Mnemonic.RET);

        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64Register.X29, insn.Op0Reg);
        
        Assert.Equal("0x00000000 RET X29", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD65F0BFF, Arm64Mnemonic.RETAA);
        Assert.Equal("0x00000000 RETAA", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD65F0FFF, Arm64Mnemonic.RETAB);
        Assert.Equal("0x00000000 RETAB", insn.ToString());
    }

    [Fact]
    public void TestBrFamily()
    {
        var insn = DisassembleAndCheckMnemonic(0xD61F0000, Arm64Mnemonic.BR);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64Register.X0, insn.Op0Reg);
        
        Assert.Equal("0x00000000 BR X0", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD71F0001, Arm64Mnemonic.BRAA);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.X0, insn.Op0Reg);
        Assert.Equal(Arm64Register.X1, insn.Op1Reg);
        
        Assert.Equal("0x00000000 BRAA X0, X1", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD71F0401, Arm64Mnemonic.BRAB);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.X0, insn.Op0Reg);
        Assert.Equal(Arm64Register.X1, insn.Op1Reg);
        
        Assert.Equal("0x00000000 BRAB X0, X1", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD61F081F, Arm64Mnemonic.BRAAZ);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64Register.X0, insn.Op0Reg);
        
        Assert.Equal("0x00000000 BRAAZ X0", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD61F0C1F, Arm64Mnemonic.BRABZ);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        
        Assert.Equal(Arm64Register.X0, insn.Op0Reg);
        
        Assert.Equal("0x00000000 BRABZ X0", insn.ToString());
    }
}