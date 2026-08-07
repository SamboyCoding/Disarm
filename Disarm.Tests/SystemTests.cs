using Disarm.InternalDisassembly;
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

    [Fact]
    public void TestSystemRegisterMoves()
    {
        var mrs = DisassembleAndCheckMnemonic(0xD53BD055, Arm64Mnemonic.MRS);
        Assert.Equal(Arm64Register.X21, mrs.Op0Reg);
        Assert.Equal(Arm64OperandKind.Immediate, mrs.Op1Kind);
        Assert.Equal(0xDE82L, mrs.Op1Imm);
        Assert.Equal("0x00000000 MRS X21, TPIDR_EL0", mrs.ToString());

        var msr = DisassembleAndCheckMnemonic(0xD51BD055, Arm64Mnemonic.MSR);
        Assert.Equal(Arm64OperandKind.Immediate, msr.Op0Kind);
        Assert.Equal(0xDE82L, msr.Op0Imm);
        Assert.Equal(Arm64Register.X21, msr.Op1Reg);
        Assert.Equal("0x00000000 MSR TPIDR_EL0, X21", msr.ToString());

        var nzcv = DisassembleAndCheckMnemonic(0xD53B4203, Arm64Mnemonic.MRS);
        Assert.Equal("0x00000000 MRS X3, NZCV", nzcv.ToString());

        var cntvct = DisassembleAndCheckMnemonic(0xD53BE044, Arm64Mnemonic.MRS);
        Assert.Equal("0x00000000 MRS X4, CNTVCT_EL0", cntvct.ToString());

        //unmapped system registers keep the raw immediate
        var unmapped = DisassembleAndCheckMnemonic(0xD5300000, Arm64Mnemonic.MRS);
        Assert.Equal(0x8000L, unmapped.Op1Imm);
        Assert.Equal("0x00000000 MRS X0, 0x8000", unmapped.ToString());
    }

    [Fact]
    public void TestUndefined()
    {
        DisassembleAndCheckMnemonic(0x00000000, Arm64Mnemonic.UDF);

        var insn = DisassembleAndCheckMnemonic(0x0000FFFF, Arm64Mnemonic.UDF);
        Assert.Equal(0xFFFF, insn.Op0Imm);
        Assert.Equal("0x00000000 UDF 0xFFFF", insn.ToString());
    }
}