using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

public class SimdTest : BaseDisarmTest
{
    public SimdTest(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void TestSimdInstruction() 
        => DisassembleAndCheckMnemonic(0x4EA0_1C08, Arm64Mnemonic.MOV);

    [Fact]
    public void TestScvtf() 
        => DisassembleAndCheckMnemonic(0x1E2202A1U, Arm64Mnemonic.SCVTF);

    [Fact]
    public void Test2SourceFp() 
        => DisassembleAndCheckMnemonic(0x1E201820U, Arm64Mnemonic.FDIV);

    [Fact]
    public void TestFp16Scvtf()
    {
        var result = DisassembleAndCheckMnemonic(0x5E21D800U, Arm64Mnemonic.SCVTF);
        Assert.Equal(Arm64Register.S0, result.Op0Reg);
    }

    [Fact]
    public void TestFpCompare()
    {
        var result = DisassembleAndCheckMnemonic(0x1E602020U, Arm64Mnemonic.FCMP);
        Assert.Equal(Arm64Register.D1, result.Op0Reg);
        Assert.Equal(Arm64Register.D0, result.Op1Reg);
    }

    [Fact]
    public void TestFsqrt()
    {
        var result = DisassembleAndCheckMnemonic(0x1E61C020U, Arm64Mnemonic.FSQRT);
        Assert.Equal(Arm64Register.D0, result.Op0Reg);
        Assert.Equal(Arm64Register.D1, result.Op1Reg);
    }

    [Fact]
    public void TestFcsel()
    {
        var result = DisassembleAndCheckMnemonic(0x1E281C00U, Arm64Mnemonic.FCSEL);
        Assert.Equal(Arm64Register.S0, result.Op0Reg);
        Assert.Equal(Arm64Register.S0, result.Op1Reg);
        Assert.Equal(Arm64Register.S8, result.Op2Reg);
        Assert.Equal(Arm64ConditionCode.NE, result.FinalOpConditionCode);
    }

    [Fact]
    public void TestMovi()
    {
        var result = DisassembleAndCheckMnemonic(0x2F00E400U, Arm64Mnemonic.MOVI);
        Assert.Equal(Arm64Register.D0, result.Op0Reg);
        Assert.Equal(0, result.Op1Imm);
    }

    [Fact]
    public void TestAdvancedSimdCopy()
    {
        //MOV V0.S[1], V1.S[0]
        var result = DisassembleAndCheckMnemonic(0x6E0C0420U, Arm64Mnemonic.MOV);
        Assert.Equal(Arm64OperandKind.VectorRegisterElement, result.Op0Kind);
        Assert.Equal(Arm64OperandKind.VectorRegisterElement, result.Op1Kind);
        Assert.Equal(Arm64Register.V0, result.Op0Reg);
        Assert.Equal(Arm64Register.V1, result.Op1Reg);
        Assert.Equal(1, result.Op0VectorElement.Index);
        Assert.Equal(0, result.Op1VectorElement.Index);
        Assert.Equal(Arm64VectorElementWidth.S, result.Op0VectorElement.Width);
        Assert.Equal(Arm64VectorElementWidth.S, result.Op1VectorElement.Width);
    }

    [Fact]
    public void TestMixedVectorElementToRegMov()
    {
        var result = DisassembleAndCheckMnemonic(0x5E0C0401, Arm64Mnemonic.MOV);
        Assert.Equal(Arm64OperandKind.Register, result.Op0Kind);
        Assert.Equal(Arm64OperandKind.VectorRegisterElement, result.Op1Kind);
        Assert.Equal(Arm64Register.S1, result.Op0Reg);
        Assert.Equal(Arm64Register.V0, result.Op1Reg);
        Assert.Equal(Arm64VectorElementWidth.S, result.Op1VectorElement.Width);
        Assert.Equal(1, result.Op1VectorElement.Index);
    }

    [Fact]
    public void TestFmovImmediateToScalar()
    {
        var result = DisassembleAndCheckMnemonic(0x1E3E1000, Arm64Mnemonic.FMOV);
        Assert.Equal(Arm64OperandKind.Register, result.Op0Kind);
        Assert.Equal(Arm64OperandKind.FloatingPointImmediate, result.Op1Kind);
        Assert.Equal(Arm64Register.S0, result.Op0Reg);
        Assert.Equal(-1, result.Op1FpImm);
    }
}
